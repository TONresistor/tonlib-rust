//! TON Payment Channels - Instant, Fee-Free Off-Chain Payments
//!
//! This crate provides payment channel functionality for the TON network,
//! enabling instant, fee-free off-chain payments between two parties.
//!
//! # Overview
//!
//! Payment channels allow two parties to transact instantly without submitting
//! every transaction to the blockchain. Only the channel opening and closing
//! transactions are on-chain, while all intermediate payments happen off-chain.
//!
//! # Key Features
//!
//! - **Instant Payments**: No need to wait for blockchain confirmation
//! - **Fee-Free**: Off-chain payments don't incur transaction fees
//! - **Secure**: Cryptographic signatures ensure only valid states can be submitted
//! - **Dispute Resolution**: On-chain challenge mechanism for disagreements
//! - **Multi-Hop Payments**: Virtual channels enable payments through intermediaries
//!
//! # Architecture
//!
//! A payment channel consists of:
//!
//! - **Two Parties (A and B)**: Each with their own keypair and balance
//! - **Two Semi-Channels**: One for each direction (A→B and B→A)
//! - **State Machine**: Tracks channel lifecycle (Uninitialized → Open → Closed)
//! - **Signed States**: Cryptographically signed channel states for security
//!
//! # Channel Lifecycle
//!
//! 1. **Initialize**: Deploy channel on-chain with initial balances
//! 2. **Transact**: Exchange signed state updates off-chain
//! 3. **Close**: Either cooperatively (both sign) or uncooperatively (dispute)
//!
//! # Example: Basic Payment
//!
//! ```
//! use ton_payments::{PaymentChannel, ChannelState};
//! use ton_crypto::Ed25519Keypair;
//!
//! // Generate keypairs for both parties
//! let keypair_a = Ed25519Keypair::generate();
//! let keypair_b = Ed25519Keypair::generate();
//!
//! let channel_id = PaymentChannel::generate_channel_id();
//!
//! // Create channel from A's perspective
//! let mut channel_a = PaymentChannel::new(
//!     channel_id,
//!     keypair_a.public_key,
//!     keypair_b.public_key,
//!     1000,  // A's initial balance
//!     1000,  // B's initial balance
//!     Some(keypair_a.clone()),
//!     true,  // We are party A
//! );
//!
//! // Create channel from B's perspective
//! let mut channel_b = PaymentChannel::new(
//!     channel_id,
//!     keypair_a.public_key,
//!     keypair_b.public_key,
//!     1000,
//!     1000,
//!     Some(keypair_b.clone()),
//!     false,  // We are party B
//! );
//!
//! // Initialize both channels
//! channel_a.initialize().unwrap();
//! channel_b.initialize().unwrap();
//!
//! // A pays B 100 (off-chain)
//! let signed_state = channel_a.make_payment(100).unwrap();
//!
//! // B receives the payment
//! channel_b.receive_payment(signed_state).unwrap();
//!
//! // Check balances
//! assert_eq!(channel_a.balance_a(), 900);
//! assert_eq!(channel_a.balance_b(), 1100);
//! ```
//!
//! # Example: Conditional Payment (HTLC)
//!
//! ```
//! use ton_payments::{PaymentChannel, ConditionalPayment};
//! use ton_crypto::{sha256, Ed25519Keypair};
//!
//! let keypair_a = Ed25519Keypair::generate();
//! let keypair_b = Ed25519Keypair::generate();
//! let channel_id = PaymentChannel::generate_channel_id();
//!
//! let pk_a = keypair_a.public_key;
//! let pk_b = keypair_b.public_key;
//!
//! let mut channel_a = PaymentChannel::new(
//!     channel_id, pk_a, pk_b,
//!     1000, 1000, Some(keypair_a), true,
//! );
//! let mut channel_b = PaymentChannel::new(
//!     channel_id, pk_a, pk_b,
//!     1000, 1000, Some(keypair_b), false,
//! );
//!
//! channel_a.initialize().unwrap();
//! channel_b.initialize().unwrap();
//!
//! // Create a hash-locked payment
//! let preimage = b"secret_preimage";
//! let hash_lock = sha256(preimage);
//!
//! // A creates conditional payment to B
//! let signed = channel_a.make_conditional_payment(200, hash_lock, 9999).unwrap();
//! channel_b.receive_payment(signed).unwrap();
//!
//! // B reveals preimage to claim the payment
//! channel_b.settle_conditional(&hash_lock, preimage).unwrap();
//! ```
//!
//! # Virtual Channels (Multi-Hop Payments)
//!
//! Virtual channels enable payments between parties without a direct channel:
//!
//! ```text
//! Alice ←──Channel──→ Bob ←──Channel──→ Charlie
//! ```
//!
//! Alice can pay Charlie through Bob using HTLC:
//!
//! 1. Charlie generates secret R, sends hash H(R) to Alice
//! 2. Alice creates conditional payment to Bob: "Pay if you know R"
//! 3. Bob creates conditional payment to Charlie: "Pay if you know R"
//! 4. Charlie reveals R to Bob, claims payment
//! 5. Bob reveals R to Alice, claims payment
//!
//! # TL-B Structures
//!
//! The crate implements the following TL-B structures:
//!
//! ```tlb
//! semi_channel_body$_ seqno:uint64 sent:Grams conditionals:HashmapE 32 ConditionalPayment
//!                     = SemiChannelBody;
//!
//! signed_semi_channel$_ sig:bits512 state:^SemiChannelBody = SignedSemiChannel;
//!
//! conditional_payment$_ amount:Grams condition:^Cell = ConditionalPayment;
//! ```
//!
//! # References
//!
//! - [TON Payment Channels Smart Contract](https://github.com/ton-blockchain/payment-channels)
//! - [TON Payment Network Implementation](https://github.com/xssnick/ton-payment-network)

pub mod channel;
pub mod conditional;
pub mod error;
pub mod messages;
pub mod onchain;
pub mod state;
pub mod r#virtual;

// Re-export main types for convenience
pub use channel::{Address, ChannelConfig, ChannelState, PaymentChannel, SemiChannel};
pub use conditional::{
    generate_preimage, hash_preimage, ConditionalPayment, ConditionalPaymentBuilder,
    SettledConditional, ConditionType, ConditionEvaluator, DefaultConditionEvaluator,
};
pub use error::{PaymentError, PaymentResult};
pub use messages::{
    ChallengeStateMessage, CooperativeCloseMessage, FinishUncooperativeCloseMessage,
    InitChannelMessage, MessageTag, P2PMessage, SettleConditionalMessage,
    StartUncooperativeCloseMessage, TopUpMessage,
};
pub use r#virtual::{
    htlc, HtlcPaymentRequest, PaymentHop, VirtualChannel, VirtualChannelBuilder,
    VirtualChannelState,
};
pub use state::{
    ChannelStateData, SemiChannel as SemiChannelState, SemiChannelBody, SignedChannelState, SignedSemiChannel,
    StateCommitment, ConditionalsMerkleTree, StateHistory, AcceptedState,
};

// On-chain integration types
pub use onchain::{
    build_challenge_state_body, build_cooperative_close_body, build_cooperative_commit_body,
    build_finish_uncooperative_close_body, build_init_channel_body, build_internal_message,
    build_settle_conditionals_body, build_start_uncooperative_close_body, build_top_up_body,
    OnchainChannelData, OnchainChannelManager, OnchainChannelState,
    OP_CHALLENGE_QUARANTINED_STATE, OP_COOPERATIVE_CLOSE, OP_COOPERATIVE_COMMIT,
    OP_FINISH_UNCOOPERATIVE_CLOSE, OP_INIT_CHANNEL, OP_SETTLE_CONDITIONALS,
    OP_START_UNCOOPERATIVE_CLOSE, OP_TOP_UP_BALANCE, GET_CHANNEL_DATA, GET_CHANNEL_STATE,
};

#[cfg(test)]
mod tests {
    use super::*;
    use ton_crypto::Ed25519Keypair;

    #[test]
    fn test_full_payment_flow() {
        // Setup
        let keypair_a = Ed25519Keypair::generate();
        let keypair_b = Ed25519Keypair::generate();
        let channel_id = PaymentChannel::generate_channel_id();

        let pk_a = keypair_a.public_key;
        let pk_b = keypair_b.public_key;

        let mut channel_a = PaymentChannel::new(
            channel_id,
            pk_a,
            pk_b,
            1000,
            1000,
            Some(keypair_a),
            true,
        );

        let mut channel_b = PaymentChannel::new(
            channel_id,
            pk_a,
            pk_b,
            1000,
            1000,
            Some(keypair_b),
            false,
        );

        // Initialize
        channel_a.initialize().unwrap();
        channel_b.initialize().unwrap();

        // Multiple payments A -> B
        for amount in [100, 50, 25] {
            let signed = channel_a.make_payment(amount).unwrap();
            channel_b.receive_payment(signed).unwrap();
        }

        // Payment B -> A
        let signed = channel_b.make_payment(75).unwrap();
        channel_a.receive_payment(signed).unwrap();

        // Final balances: A = 1000 - 175 + 75 = 900, B = 1000 + 175 - 75 = 1100
        assert_eq!(channel_a.balance_a(), 900);
        assert_eq!(channel_a.balance_b(), 1100);
        assert_eq!(channel_b.balance_a(), 900);
        assert_eq!(channel_b.balance_b(), 1100);

        // Cooperative close
        let sig_a = channel_a.sign_for_close().unwrap();
        let sig_b = channel_b.sign_for_close().unwrap();

        let signed_state = channel_a.cooperative_close(sig_a, sig_b).unwrap();
        assert_eq!(channel_a.state, ChannelState::Settled);

        // Verify the final state
        assert!(signed_state.verify(&pk_a, &pk_b).is_ok());
    }

    #[test]
    fn test_conditional_payment_flow() {
        let keypair_a = Ed25519Keypair::generate();
        let keypair_b = Ed25519Keypair::generate();
        let channel_id = PaymentChannel::generate_channel_id();

        let pk_a = keypair_a.public_key;
        let pk_b = keypair_b.public_key;

        let mut channel_a = PaymentChannel::new(
            channel_id,
            pk_a,
            pk_b,
            1000,
            1000,
            Some(keypair_a),
            true,
        );

        let mut channel_b = PaymentChannel::new(
            channel_id,
            pk_a,
            pk_b,
            1000,
            1000,
            Some(keypair_b),
            false,
        );

        channel_a.initialize().unwrap();
        channel_b.initialize().unwrap();

        // Create conditional payment
        let preimage = generate_preimage();
        let hash_lock = hash_preimage(&preimage);

        let signed = channel_a
            .make_conditional_payment(300, hash_lock, 9999)
            .unwrap();
        channel_b.receive_payment(signed).unwrap();

        // A's balance reflects pending conditional
        assert_eq!(channel_a.balance_a(), 700);

        // B settles by revealing preimage
        let amount = channel_b.settle_conditional(&hash_lock, &preimage).unwrap();
        assert_eq!(amount, 300);
    }

    #[test]
    fn test_virtual_channel_flow() {
        // Simulating: Alice -> Bob -> Charlie
        let alice = Ed25519Keypair::generate().public_key;
        let bob = Ed25519Keypair::generate().public_key;
        let charlie = Ed25519Keypair::generate().public_key;

        // Charlie creates payment request
        let (request, preimage) = htlc::create_payment_request(500, 10000);

        // Alice creates virtual channel
        let vc = VirtualChannelBuilder::new(alice, charlie, 500)
            .with_hash_lock(request.hash_lock)
            .with_deadline(10000)
            .with_fee_per_hop(10)
            .with_timeout_decrement(1000)
            .with_route(vec![(bob, 1), (charlie, 2)])
            .build()
            .unwrap();

        // Create conditionals for each hop
        let conditionals = vc.create_conditionals();
        assert_eq!(conditionals.len(), 2);

        // First hop (Alice -> Bob) has higher amount for fees
        assert_eq!(conditionals[0].amount, 520); // 500 + 10*2
        assert_eq!(conditionals[1].amount, 510); // 500 + 10*1

        // Verify preimage matches hash lock
        assert!(htlc::verify_preimage(&preimage, &request.hash_lock));
    }

    #[test]
    fn test_message_serialization() {
        let party_a = Ed25519Keypair::generate().public_key;
        let party_b = Ed25519Keypair::generate().public_key;

        let msg = InitChannelMessage::new(12345, party_a, party_b, 1000, 2000)
            .with_min_balances(100, 200)
            .with_challenge_period(86400);

        let serialized = msg.serialize();
        let deserialized = InitChannelMessage::deserialize(&serialized).unwrap();

        assert_eq!(msg.channel_id, deserialized.channel_id);
        assert_eq!(msg.party_a, deserialized.party_a);
        assert_eq!(msg.party_b, deserialized.party_b);
    }

    #[test]
    fn test_uncooperative_close_flow() {
        let keypair_a = Ed25519Keypair::generate();
        let keypair_b = Ed25519Keypair::generate();
        let channel_id = PaymentChannel::generate_channel_id();

        let pk_a = keypair_a.public_key;
        let pk_b = keypair_b.public_key;

        let config = ChannelConfig {
            challenge_period: 3600,
            ..Default::default()
        };

        let mut channel_a = PaymentChannel::new(
            channel_id,
            pk_a,
            pk_b,
            1000,
            1000,
            Some(keypair_a),
            true,
        )
        .with_config(config);

        channel_a.initialize().unwrap();

        // Make some payments
        let _ = channel_a.make_payment(100).unwrap();

        // Start uncooperative close
        let current_time = 1000;
        let signed = channel_a.start_uncooperative_close(current_time).unwrap();

        match &channel_a.state {
            ChannelState::ClosureStarted { deadline, .. } => {
                assert_eq!(*deadline, current_time + 3600);
            }
            _ => panic!("Expected ClosureStarted state"),
        }

        // Verify signed state
        assert!(signed.verify(&pk_a).is_ok());

        // Finalize after challenge period
        let (balance_a, balance_b) = channel_a.finalize(current_time + 3601).unwrap();
        assert_eq!(balance_a, 900);
        assert_eq!(balance_b, 1100);
        assert_eq!(channel_a.state, ChannelState::Settled);
    }

    // ========================================================================
    // REPLAY ATTACK PROTECTION TESTS (Phase 1)
    // ========================================================================

    #[test]
    fn test_cannot_replay_old_state() {
        // Setup
        let keypair_a = Ed25519Keypair::generate();
        let keypair_b = Ed25519Keypair::generate();
        let channel_id = PaymentChannel::generate_channel_id();

        let pk_a = keypair_a.public_key;
        let pk_b = keypair_b.public_key;

        let mut channel_a = PaymentChannel::new(
            channel_id,
            pk_a,
            pk_b,
            1000,
            1000,
            Some(keypair_a),
            true,
        );

        let mut channel_b = PaymentChannel::new(
            channel_id,
            pk_a,
            pk_b,
            1000,
            1000,
            Some(keypair_b),
            false,
        );

        channel_a.initialize().unwrap();
        channel_b.initialize().unwrap();

        // A pays B 100
        let signed_100 = channel_a.make_payment(100).unwrap();
        channel_b.receive_payment(signed_100.clone()).unwrap();

        // A pays B another 50 (now total 150)
        let signed_150 = channel_a.make_payment(50).unwrap();
        channel_b.receive_payment(signed_150).unwrap();

        // Try to replay the old 100 payment
        // This should fail because seqno is not newer than what B already has
        let result = channel_b.receive_payment(signed_100);
        assert!(result.is_err());
        match result {
            Err(PaymentError::StateNotNewer { .. }) => {}
            other => panic!("Expected StateNotNewer error, got {:?}", other),
        }
    }

    #[test]
    fn test_cannot_replay_across_channels() {
        // Setup two channels with different IDs
        let keypair_a = Ed25519Keypair::generate();
        let keypair_b = Ed25519Keypair::generate();
        let keypair_c = Ed25519Keypair::generate();

        let channel_id_1 = 111u128;
        let channel_id_2 = 222u128;

        // Channel 1: A <-> B
        let mut channel_1_ab = PaymentChannel::new(
            channel_id_1,
            keypair_a.public_key,
            keypair_b.public_key,
            1000,
            1000,
            Some(keypair_a.clone()),
            true,
        );

        let mut channel_1_ba = PaymentChannel::new(
            channel_id_1,
            keypair_a.public_key,
            keypair_b.public_key,
            1000,
            1000,
            Some(keypair_b.clone()),
            false,
        );

        // Channel 2: A <-> C
        let mut channel_2_ac = PaymentChannel::new(
            channel_id_2,
            keypair_a.public_key,
            keypair_c.public_key,
            1000,
            1000,
            Some(keypair_a.clone()),
            true,
        );

        let mut channel_2_ca = PaymentChannel::new(
            channel_id_2,
            keypair_a.public_key,
            keypair_c.public_key,
            1000,
            1000,
            Some(keypair_c),
            false,
        );

        // Initialize
        channel_1_ab.initialize().unwrap();
        channel_1_ba.initialize().unwrap();
        channel_2_ac.initialize().unwrap();
        channel_2_ca.initialize().unwrap();

        // A pays B 100 on channel 1
        let signed = channel_1_ab.make_payment(100).unwrap();
        channel_1_ba.receive_payment(signed.clone()).unwrap();

        // Try to use same signed state on channel 2
        // This should fail because channel_id doesn't match
        let result = channel_2_ca.receive_payment(signed);
        assert!(result.is_err());
        match result {
            Err(PaymentError::InvalidChannelId { .. }) => {}
            other => panic!("Expected InvalidChannelId error, got {:?}", other),
        }
    }

    #[test]
    fn test_timestamp_ordering_enforced() {
        // Setup
        let keypair_a = Ed25519Keypair::generate();
        let keypair_b = Ed25519Keypair::generate();
        let channel_id = PaymentChannel::generate_channel_id();

        let pk_a = keypair_a.public_key;
        let pk_b = keypair_b.public_key;

        let mut channel_a = PaymentChannel::new(
            channel_id,
            pk_a,
            pk_b,
            1000,
            1000,
            Some(keypair_a),
            true,
        );

        let mut channel_b = PaymentChannel::new(
            channel_id,
            pk_a,
            pk_b,
            1000,
            1000,
            Some(keypair_b),
            false,
        );

        channel_a.initialize().unwrap();
        channel_b.initialize().unwrap();

        // A pays B with block_height = 100
        channel_a.set_block_height(100);
        let signed_100 = channel_a.make_payment(50).unwrap();
        channel_b.receive_payment(signed_100).unwrap();

        // A tries to pay with older block_height = 50 (before accepting 100)
        channel_a.set_block_height(50);
        let signed_50 = channel_a.make_payment(50).unwrap();

        // This should fail because block_height is not monotonically increasing
        let result = channel_b.receive_payment(signed_50);
        assert!(result.is_err());
        match result {
            Err(PaymentError::StateNotProgressing { .. }) => {}
            other => panic!("Expected StateNotProgressing error, got {:?}", other),
        }
    }

    #[test]
    fn test_challenge_binding() {
        // Setup
        let keypair_a = Ed25519Keypair::generate();
        let keypair_b = Ed25519Keypair::generate();
        let channel_id = PaymentChannel::generate_channel_id();

        let pk_a = keypair_a.public_key;
        let pk_b = keypair_b.public_key;

        let mut channel_a = PaymentChannel::new(
            channel_id,
            pk_a,
            pk_b,
            1000,
            1000,
            Some(keypair_a.clone()),
            true,
        );

        let mut channel_b = PaymentChannel::new(
            channel_id,
            pk_a,
            pk_b,
            1000,
            1000,
            Some(keypair_b),
            false,
        );

        channel_a.initialize().unwrap();
        channel_b.initialize().unwrap();

        // Get initial challenges (both random, different)
        let challenge_a = channel_a.challenge();
        let challenge_b = channel_b.challenge();
        assert_ne!(challenge_a, challenge_b);

        // A pays B - challenge is embedded in signed state
        let signed = channel_a.make_payment(50).unwrap();
        // B accepts first state, syncs challenge
        channel_b.receive_payment(signed.clone()).unwrap();
        assert_eq!(channel_b.challenge(), challenge_a);

        // Now modify the signed state's challenge (simulate attack)
        // Create a new state with wrong challenge
        let mut wrong_state = signed.state.clone();
        wrong_state.challenge = [255u8; 32];

        let mut wrong_signed = signed.clone();
        wrong_signed.state = wrong_state;

        // Try to apply - should fail (even without signature check,
        // the challenge won't match once established)
        let result = channel_b.receive_payment(wrong_signed);
        assert!(result.is_err());
        match result {
            Err(PaymentError::InvalidChallenge) => {}
            Err(PaymentError::SignatureVerificationFailed) => {
                // This is OK - signature fails because we modified the state
            }
            other => panic!("Expected InvalidChallenge or SignatureVerificationFailed, got {:?}", other),
        }
    }

    #[test]
    fn test_signature_invalid_if_context_modified() {
        // Setup
        let keypair_a = Ed25519Keypair::generate();
        let keypair_b = Ed25519Keypair::generate();
        let channel_id = PaymentChannel::generate_channel_id();

        let pk_a = keypair_a.public_key;
        let pk_b = keypair_b.public_key;

        let mut channel_a = PaymentChannel::new(
            channel_id,
            pk_a,
            pk_b,
            1000,
            1000,
            Some(keypair_a),
            true,
        );

        let mut channel_b = PaymentChannel::new(
            channel_id,
            pk_a,
            pk_b,
            1000,
            1000,
            Some(keypair_b),
            false,
        );

        channel_a.initialize().unwrap();
        channel_b.initialize().unwrap();

        // Create a signed payment
        channel_a.set_block_height(100);
        let signed = channel_a.make_payment(50).unwrap();

        // First reception succeeds
        channel_b.receive_payment(signed.clone()).unwrap();

        // Now try to modify the block_height and replay
        let mut modified = signed.clone();
        modified.state.block_height = 200;

        let result = channel_b.receive_payment(modified);
        // Should fail with signature verification error (signature no longer valid)
        assert!(result.is_err());
        match result {
            Err(PaymentError::SignatureVerificationFailed) => {}
            other => panic!("Expected SignatureVerificationFailed, got {:?}", other),
        }
    }

    #[test]
    fn test_replay_protection_integration() {
        // Full scenario: A pays B multiple times with increasing block heights
        let keypair_a = Ed25519Keypair::generate();
        let keypair_b = Ed25519Keypair::generate();
        let channel_id = PaymentChannel::generate_channel_id();

        let pk_a = keypair_a.public_key;
        let pk_b = keypair_b.public_key;

        let mut channel_a = PaymentChannel::new(
            channel_id,
            pk_a,
            pk_b,
            1000,
            1000,
            Some(keypair_a),
            true,
        );

        let mut channel_b = PaymentChannel::new(
            channel_id,
            pk_a,
            pk_b,
            1000,
            1000,
            Some(keypair_b),
            false,
        );

        channel_a.initialize().unwrap();
        channel_b.initialize().unwrap();

        // Payment 1: block_height = 100
        channel_a.set_block_height(100);
        let sig1 = channel_a.make_payment(100).unwrap();
        channel_b.receive_payment(sig1.clone()).unwrap();
        assert_eq!(channel_b.balance_b(), 1100);

        // Payment 2: block_height = 200
        channel_a.set_block_height(200);
        let sig2 = channel_a.make_payment(100).unwrap();
        channel_b.receive_payment(sig2.clone()).unwrap();
        assert_eq!(channel_b.balance_b(), 1200);

        // Try to replay payment 1 (old block_height)
        let result = channel_b.receive_payment(sig1);
        assert!(result.is_err());

        // Try to replay payment 2 (same block_height)
        let result = channel_b.receive_payment(sig2);
        assert!(result.is_err());

        // Valid payment 3: block_height = 300
        channel_a.set_block_height(300);
        let sig3 = channel_a.make_payment(50).unwrap();
        channel_b.receive_payment(sig3).unwrap();
        assert_eq!(channel_b.balance_b(), 1250);
    }

    #[test]
    fn test_channel_reopen_changes_challenge() {
        // Demonstrate that each new channel instance has a different challenge
        let keypair_a = Ed25519Keypair::generate();
        let keypair_b = Ed25519Keypair::generate();

        let pk_a = keypair_a.public_key;
        let pk_b = keypair_b.public_key;

        // Create and use first channel
        let channel_id_1 = PaymentChannel::generate_channel_id();
        let mut channel_a1 = PaymentChannel::new(
            channel_id_1,
            pk_a,
            pk_b,
            1000,
            1000,
            Some(keypair_a.clone()),
            true,
        );

        let mut channel_b1 = PaymentChannel::new(
            channel_id_1,
            pk_a,
            pk_b,
            1000,
            1000,
            Some(keypair_b.clone()),
            false,
        );

        channel_a1.initialize().unwrap();
        channel_b1.initialize().unwrap();

        // Make a payment - channels sync their challenges
        let challenge_a1 = channel_a1.challenge();
        let signed1 = channel_a1.make_payment(50).unwrap();
        channel_b1.receive_payment(signed1).unwrap();
        let challenge_b1 = channel_b1.challenge();
        assert_eq!(challenge_a1, challenge_b1);

        // Create a new channel instance with different channel_id
        // (simulates channel being fully replaced)
        let channel_id_2 = PaymentChannel::generate_channel_id();
        assert_ne!(channel_id_1, channel_id_2);

        let mut channel_a2 = PaymentChannel::new(
            channel_id_2,
            pk_a,
            pk_b,
            1000,
            1000,
            Some(keypair_a),
            true,
        );

        let mut channel_b2 = PaymentChannel::new(
            channel_id_2,
            pk_a,
            pk_b,
            1000,
            1000,
            Some(keypair_b),
            false,
        );

        channel_a2.initialize().unwrap();
        channel_b2.initialize().unwrap();

        // New channels have different challenges
        let challenge_a2 = channel_a2.challenge();
        let challenge_b2 = channel_b2.challenge();
        assert_ne!(challenge_a1, challenge_a2);
        assert_ne!(challenge_b1, challenge_b2);

        // Each channel instance generates its own challenge on creation
        // This prevents old states from being replayed across channel lifetimes
        // (when using different channel_ids)

        // New payment works on new channel
        let signed2 = channel_a2.make_payment(50).unwrap();
        channel_b2.receive_payment(signed2).unwrap();
        assert_eq!(channel_a2.balance_a(), 950);
        assert_eq!(channel_b2.balance_b(), 1050);
    }
}
