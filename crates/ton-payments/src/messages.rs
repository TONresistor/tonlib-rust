//! Channel operation messages for TON Payment Channels.
//!
//! This module defines the messages exchanged between parties and
//! submitted on-chain for channel operations.
//!
//! # Message Types
//!
//! - **InitChannel**: Deploy and initialize a new channel
//! - **TopUp**: Add funds to the channel
//! - **CooperativeClose**: Close with mutual agreement
//! - **StartUncooperativeClose**: Begin unilateral close
//! - **ChallengeState**: Submit a newer state during dispute
//! - **FinishUncooperativeClose**: Complete close after challenge period
//! - **SettleConditional**: Settle a conditional payment with preimage

use crate::channel::Address;
use crate::error::{PaymentError, PaymentResult};
use crate::state::{SignedChannelState, SignedSemiChannel};
use ton_crypto::sha256;

/// Message tag for identifying message types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum MessageTag {
    /// Initialize a new channel.
    InitChannel = 0x1,
    /// Add funds to the channel.
    TopUp = 0x2,
    /// Cooperative close with both signatures.
    CooperativeClose = 0x3,
    /// Start uncooperative close.
    StartUncooperativeClose = 0x4,
    /// Challenge with a newer state.
    ChallengeState = 0x5,
    /// Finish uncooperative close after timeout.
    FinishUncooperativeClose = 0x6,
    /// Settle a conditional payment.
    SettleConditional = 0x7,
}

impl MessageTag {
    /// Convert from u32.
    pub fn from_u32(value: u32) -> Option<Self> {
        match value {
            0x1 => Some(MessageTag::InitChannel),
            0x2 => Some(MessageTag::TopUp),
            0x3 => Some(MessageTag::CooperativeClose),
            0x4 => Some(MessageTag::StartUncooperativeClose),
            0x5 => Some(MessageTag::ChallengeState),
            0x6 => Some(MessageTag::FinishUncooperativeClose),
            0x7 => Some(MessageTag::SettleConditional),
            _ => None,
        }
    }
}

/// Initialize channel message.
///
/// Sent to deploy a new payment channel on-chain.
#[derive(Debug, Clone)]
pub struct InitChannelMessage {
    /// Unique channel identifier.
    pub channel_id: u128,

    /// Address of party A.
    pub party_a: Address,

    /// Address of party B.
    pub party_b: Address,

    /// Initial balance of party A (in nanotons).
    pub balance_a: u128,

    /// Initial balance of party B (in nanotons).
    pub balance_b: u128,

    /// Minimum balance party A must maintain.
    pub min_balance_a: u128,

    /// Minimum balance party B must maintain.
    pub min_balance_b: u128,

    /// Challenge period duration in seconds.
    pub challenge_period: u32,
}

impl InitChannelMessage {
    /// Create a new init channel message.
    pub fn new(
        channel_id: u128,
        party_a: Address,
        party_b: Address,
        balance_a: u128,
        balance_b: u128,
    ) -> Self {
        Self {
            channel_id,
            party_a,
            party_b,
            balance_a,
            balance_b,
            min_balance_a: 0,
            min_balance_b: 0,
            challenge_period: 86400, // 24 hours default
        }
    }

    /// Set minimum balances.
    pub fn with_min_balances(mut self, min_a: u128, min_b: u128) -> Self {
        self.min_balance_a = min_a;
        self.min_balance_b = min_b;
        self
    }

    /// Set challenge period.
    pub fn with_challenge_period(mut self, period: u32) -> Self {
        self.challenge_period = period;
        self
    }

    /// Serialize to bytes.
    pub fn serialize(&self) -> Vec<u8> {
        let mut data = Vec::new();

        // Tag
        data.extend_from_slice(&(MessageTag::InitChannel as u32).to_be_bytes());

        // Channel ID
        data.extend_from_slice(&self.channel_id.to_be_bytes());

        // Parties
        data.extend_from_slice(&self.party_a);
        data.extend_from_slice(&self.party_b);

        // Balances
        data.extend_from_slice(&self.balance_a.to_be_bytes());
        data.extend_from_slice(&self.balance_b.to_be_bytes());

        // Minimum balances
        data.extend_from_slice(&self.min_balance_a.to_be_bytes());
        data.extend_from_slice(&self.min_balance_b.to_be_bytes());

        // Challenge period
        data.extend_from_slice(&self.challenge_period.to_be_bytes());

        data
    }

    /// Deserialize from bytes.
    pub fn deserialize(data: &[u8]) -> PaymentResult<Self> {
        if data.len() < 148 {
            return Err(PaymentError::DeserializationError(
                "Data too short for InitChannelMessage".to_string(),
            ));
        }

        let tag = u32::from_be_bytes(data[0..4].try_into().unwrap());
        if tag != MessageTag::InitChannel as u32 {
            return Err(PaymentError::DeserializationError(
                format!("Invalid tag: expected {}, got {}", MessageTag::InitChannel as u32, tag),
            ));
        }

        let channel_id = u128::from_be_bytes(data[4..20].try_into().unwrap());

        let mut party_a = [0u8; 32];
        party_a.copy_from_slice(&data[20..52]);

        let mut party_b = [0u8; 32];
        party_b.copy_from_slice(&data[52..84]);

        let balance_a = u128::from_be_bytes(data[84..100].try_into().unwrap());
        let balance_b = u128::from_be_bytes(data[100..116].try_into().unwrap());
        let min_balance_a = u128::from_be_bytes(data[116..132].try_into().unwrap());
        let min_balance_b = u128::from_be_bytes(data[132..148].try_into().unwrap());

        let challenge_period = if data.len() >= 152 {
            u32::from_be_bytes(data[148..152].try_into().unwrap())
        } else {
            86400
        };

        Ok(Self {
            channel_id,
            party_a,
            party_b,
            balance_a,
            balance_b,
            min_balance_a,
            min_balance_b,
            challenge_period,
        })
    }
}

/// Top-up message to add funds to the channel.
#[derive(Debug, Clone)]
pub struct TopUpMessage {
    /// Channel ID.
    pub channel_id: u128,

    /// Which party is topping up (true = A, false = B).
    pub is_party_a: bool,

    /// Amount to add (in nanotons).
    pub amount: u128,
}

impl TopUpMessage {
    /// Create a new top-up message.
    pub fn new(channel_id: u128, is_party_a: bool, amount: u128) -> Self {
        Self {
            channel_id,
            is_party_a,
            amount,
        }
    }

    /// Serialize to bytes.
    pub fn serialize(&self) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&(MessageTag::TopUp as u32).to_be_bytes());
        data.extend_from_slice(&self.channel_id.to_be_bytes());
        data.push(if self.is_party_a { 1 } else { 0 });
        data.extend_from_slice(&self.amount.to_be_bytes());
        data
    }
}

/// Cooperative close message.
#[derive(Debug, Clone)]
pub struct CooperativeCloseMessage {
    /// The signed channel state with both signatures.
    pub signed_state: SignedChannelState,
}

impl CooperativeCloseMessage {
    /// Create a new cooperative close message.
    pub fn new(signed_state: SignedChannelState) -> Self {
        Self { signed_state }
    }

    /// Serialize to bytes.
    pub fn serialize(&self) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&(MessageTag::CooperativeClose as u32).to_be_bytes());
        data.extend_from_slice(&self.signed_state.serialize());
        data
    }
}

/// Start uncooperative close message.
#[derive(Debug, Clone)]
pub struct StartUncooperativeCloseMessage {
    /// Channel ID.
    pub channel_id: u128,

    /// Our signed semi-channel state.
    pub signed_semi_channel: SignedSemiChannel,
}

impl StartUncooperativeCloseMessage {
    /// Create a new start uncooperative close message.
    pub fn new(channel_id: u128, signed_semi_channel: SignedSemiChannel) -> Self {
        Self {
            channel_id,
            signed_semi_channel,
        }
    }

    /// Serialize to bytes.
    pub fn serialize(&self) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&(MessageTag::StartUncooperativeClose as u32).to_be_bytes());
        data.extend_from_slice(&self.channel_id.to_be_bytes());
        data.extend_from_slice(&self.signed_semi_channel.serialize());
        data
    }
}

/// Challenge state message.
#[derive(Debug, Clone)]
pub struct ChallengeStateMessage {
    /// Channel ID.
    pub channel_id: u128,

    /// Newer signed semi-channel state.
    pub signed_semi_channel: SignedSemiChannel,
}

impl ChallengeStateMessage {
    /// Create a new challenge state message.
    pub fn new(channel_id: u128, signed_semi_channel: SignedSemiChannel) -> Self {
        Self {
            channel_id,
            signed_semi_channel,
        }
    }

    /// Serialize to bytes.
    pub fn serialize(&self) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&(MessageTag::ChallengeState as u32).to_be_bytes());
        data.extend_from_slice(&self.channel_id.to_be_bytes());
        data.extend_from_slice(&self.signed_semi_channel.serialize());
        data
    }
}

/// Finish uncooperative close message.
#[derive(Debug, Clone)]
pub struct FinishUncooperativeCloseMessage {
    /// Channel ID.
    pub channel_id: u128,
}

impl FinishUncooperativeCloseMessage {
    /// Create a new finish uncooperative close message.
    pub fn new(channel_id: u128) -> Self {
        Self { channel_id }
    }

    /// Serialize to bytes.
    pub fn serialize(&self) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&(MessageTag::FinishUncooperativeClose as u32).to_be_bytes());
        data.extend_from_slice(&self.channel_id.to_be_bytes());
        data
    }
}

/// Settle conditional payment message.
#[derive(Debug, Clone)]
pub struct SettleConditionalMessage {
    /// Channel ID.
    pub channel_id: u128,

    /// Hash of the conditional payment.
    pub condition_hash: [u8; 32],

    /// The secret preimage.
    pub preimage: Vec<u8>,
}

impl SettleConditionalMessage {
    /// Create a new settle conditional message.
    pub fn new(channel_id: u128, condition_hash: [u8; 32], preimage: Vec<u8>) -> Self {
        Self {
            channel_id,
            condition_hash,
            preimage,
        }
    }

    /// Verify the preimage matches the condition hash.
    pub fn verify(&self) -> bool {
        sha256(&self.preimage) == self.condition_hash
    }

    /// Serialize to bytes.
    pub fn serialize(&self) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&(MessageTag::SettleConditional as u32).to_be_bytes());
        data.extend_from_slice(&self.channel_id.to_be_bytes());
        data.extend_from_slice(&self.condition_hash);
        data.extend_from_slice(&(self.preimage.len() as u32).to_be_bytes());
        data.extend_from_slice(&self.preimage);
        data
    }
}

/// Peer-to-peer message for off-chain communication.
#[derive(Debug, Clone)]
pub enum P2PMessage {
    /// Request to open a channel.
    ChannelOpenRequest(InitChannelMessage),

    /// Accept channel open request.
    ChannelOpenAccept {
        channel_id: u128,
        signature: [u8; 64],
    },

    /// State update (payment).
    StateUpdate(SignedSemiChannel),

    /// Request cooperative close.
    CloseRequest {
        channel_id: u128,
        signature: [u8; 64],
    },

    /// Accept cooperative close.
    CloseAccept {
        channel_id: u128,
        signature: [u8; 64],
    },

    /// Conditional payment claim (reveal preimage).
    ConditionalClaim {
        channel_id: u128,
        condition_hash: [u8; 32],
        preimage: Vec<u8>,
    },
}

impl P2PMessage {
    /// Get the channel ID from the message.
    pub fn channel_id(&self) -> u128 {
        match self {
            P2PMessage::ChannelOpenRequest(msg) => msg.channel_id,
            P2PMessage::ChannelOpenAccept { channel_id, .. } => *channel_id,
            P2PMessage::StateUpdate(_) => 0, // State doesn't contain channel ID
            P2PMessage::CloseRequest { channel_id, .. } => *channel_id,
            P2PMessage::CloseAccept { channel_id, .. } => *channel_id,
            P2PMessage::ConditionalClaim { channel_id, .. } => *channel_id,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::SemiChannelBody;
    use ton_crypto::Ed25519Keypair;

    fn generate_address() -> Address {
        Ed25519Keypair::generate().public_key
    }

    #[test]
    fn test_message_tag() {
        assert_eq!(MessageTag::from_u32(0x1), Some(MessageTag::InitChannel));
        assert_eq!(MessageTag::from_u32(0x3), Some(MessageTag::CooperativeClose));
        assert_eq!(MessageTag::from_u32(0x99), None);
    }

    #[test]
    fn test_init_channel_message() {
        let party_a = generate_address();
        let party_b = generate_address();

        let msg = InitChannelMessage::new(12345, party_a, party_b, 1000, 2000)
            .with_min_balances(100, 200)
            .with_challenge_period(3600);

        assert_eq!(msg.channel_id, 12345);
        assert_eq!(msg.balance_a, 1000);
        assert_eq!(msg.balance_b, 2000);
        assert_eq!(msg.min_balance_a, 100);
        assert_eq!(msg.min_balance_b, 200);
        assert_eq!(msg.challenge_period, 3600);
    }

    #[test]
    fn test_init_channel_serialize_deserialize() {
        let party_a = generate_address();
        let party_b = generate_address();

        let msg = InitChannelMessage::new(99999, party_a, party_b, 5000, 6000)
            .with_min_balances(500, 600)
            .with_challenge_period(7200);

        let serialized = msg.serialize();
        let deserialized = InitChannelMessage::deserialize(&serialized).unwrap();

        assert_eq!(msg.channel_id, deserialized.channel_id);
        assert_eq!(msg.party_a, deserialized.party_a);
        assert_eq!(msg.party_b, deserialized.party_b);
        assert_eq!(msg.balance_a, deserialized.balance_a);
        assert_eq!(msg.balance_b, deserialized.balance_b);
        assert_eq!(msg.min_balance_a, deserialized.min_balance_a);
        assert_eq!(msg.min_balance_b, deserialized.min_balance_b);
    }

    #[test]
    fn test_top_up_message() {
        let msg = TopUpMessage::new(123, true, 1000);

        assert_eq!(msg.channel_id, 123);
        assert!(msg.is_party_a);
        assert_eq!(msg.amount, 1000);

        let serialized = msg.serialize();
        assert!(serialized.len() > 20);
    }

    #[test]
    fn test_start_uncooperative_close_message() {
        let keypair = Ed25519Keypair::generate();
        let body = SemiChannelBody::new();
        let signed = SignedSemiChannel::new(&keypair, body);

        let msg = StartUncooperativeCloseMessage::new(456, signed);

        assert_eq!(msg.channel_id, 456);
        let serialized = msg.serialize();
        assert!(serialized.len() > 20);
    }

    #[test]
    fn test_settle_conditional_message() {
        let preimage = b"secret_preimage";
        let hash = sha256(preimage);

        let msg = SettleConditionalMessage::new(789, hash, preimage.to_vec());

        assert_eq!(msg.channel_id, 789);
        assert_eq!(msg.condition_hash, hash);
        assert!(msg.verify());
    }

    #[test]
    fn test_settle_conditional_invalid_preimage() {
        let preimage = b"secret_preimage";
        let wrong_preimage = b"wrong";
        let hash = sha256(preimage);

        let msg = SettleConditionalMessage::new(789, hash, wrong_preimage.to_vec());

        assert!(!msg.verify());
    }

    #[test]
    fn test_p2p_message_channel_id() {
        let party_a = generate_address();
        let party_b = generate_address();
        let init_msg = InitChannelMessage::new(111, party_a, party_b, 100, 100);

        let p2p = P2PMessage::ChannelOpenRequest(init_msg);
        assert_eq!(p2p.channel_id(), 111);

        let p2p2 = P2PMessage::CloseRequest {
            channel_id: 222,
            signature: [0u8; 64],
        };
        assert_eq!(p2p2.channel_id(), 222);
    }

    #[test]
    fn test_finish_uncooperative_close_message() {
        let msg = FinishUncooperativeCloseMessage::new(999);

        assert_eq!(msg.channel_id, 999);
        let serialized = msg.serialize();
        assert_eq!(serialized.len(), 4 + 16); // tag + channel_id
    }

    #[test]
    fn test_challenge_state_message() {
        let keypair = Ed25519Keypair::generate();
        let mut body = SemiChannelBody::new();
        body.seqno = 10;
        body.sent = 500;
        let signed = SignedSemiChannel::new(&keypair, body);

        let msg = ChallengeStateMessage::new(333, signed.clone());

        assert_eq!(msg.channel_id, 333);
        assert_eq!(msg.signed_semi_channel.state.seqno, 10);
        assert_eq!(msg.signed_semi_channel.state.sent, 500);
    }
}
