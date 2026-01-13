//! Virtual Channels for multi-hop payments (HTLC).
//!
//! This module implements virtual payment channels that enable payments
//! between parties without a direct channel, using intermediaries.
//!
//! # Overview
//!
//! Virtual channels work like this:
//!
//! ```text
//! Alice ←──Channel──→ Bob ←──Channel──→ Charlie
//!
//! Alice wants to pay Charlie 100 TON:
//! 1. Charlie generates secret R, sends hash H(R) to Alice
//! 2. Alice creates conditional payment to Bob: "Pay 100 if you know R"
//! 3. Bob creates conditional payment to Charlie: "Pay 100 if you know R"
//! 4. Charlie reveals R to Bob, claims 100 TON
//! 5. Bob reveals R to Alice, claims 100 TON
//! ```
//!
//! This is the classic Hash Time-Locked Contract (HTLC) pattern.

use crate::channel::Address;
use crate::conditional::ConditionalPayment;
use crate::error::{PaymentError, PaymentResult};
use ton_crypto::sha256;

/// State of a virtual channel payment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VirtualChannelState {
    /// Payment is being set up, waiting for all hops to lock funds.
    Pending,

    /// All hops have locked funds, waiting for preimage reveal.
    Locked,

    /// Preimage revealed, payment is settling through the chain.
    Settling,

    /// Payment completed successfully.
    Completed,

    /// Payment failed or expired.
    Failed,

    /// Payment was cancelled.
    Cancelled,
}

/// A hop in a virtual channel payment route.
#[derive(Debug, Clone)]
pub struct PaymentHop {
    /// Address of the node at this hop.
    pub node: Address,

    /// The direct channel used for this hop.
    pub channel_id: u128,

    /// Amount to forward (may differ from final amount due to fees).
    pub amount: u128,

    /// Timeout for this hop (must decrease along the route).
    pub timeout: u32,

    /// Whether this hop has been locked (conditional created).
    pub locked: bool,

    /// Whether this hop has been settled (preimage revealed).
    pub settled: bool,
}

/// A virtual channel for multi-hop payments.
///
/// This represents a payment that traverses multiple direct channels
/// to reach a destination.
#[derive(Debug)]
pub struct VirtualChannel {
    /// Unique identifier for this virtual payment.
    pub payment_id: u128,

    /// Sender of the payment (first hop).
    pub sender: Address,

    /// Final receiver of the payment.
    pub receiver: Address,

    /// Amount to be received by the final receiver.
    pub amount: u128,

    /// SHA256 hash of the secret preimage.
    pub hash_lock: [u8; 32],

    /// The secret preimage (only known to receiver initially).
    /// Revealed during settlement.
    preimage: Option<[u8; 32]>,

    /// Route of payment hops from sender to receiver.
    pub hops: Vec<PaymentHop>,

    /// Current state of the virtual channel.
    pub state: VirtualChannelState,

    /// Creation timestamp.
    pub created_at: u32,

    /// Final deadline for the entire payment.
    pub deadline: u32,
}

impl VirtualChannel {
    /// Create a new virtual channel payment.
    ///
    /// # Arguments
    /// * `sender` - Address of the payment sender
    /// * `receiver` - Address of the payment receiver
    /// * `amount` - Amount to pay
    /// * `hash_lock` - Hash of the secret preimage
    /// * `deadline` - Final deadline for the payment
    pub fn new(
        sender: Address,
        receiver: Address,
        amount: u128,
        hash_lock: [u8; 32],
        deadline: u32,
    ) -> Self {
        Self {
            payment_id: Self::generate_payment_id(),
            sender,
            receiver,
            amount,
            hash_lock,
            preimage: None,
            hops: Vec::new(),
            state: VirtualChannelState::Pending,
            created_at: 0, // Should be set by caller
            deadline,
        }
    }

    /// Create a virtual channel as the receiver (with preimage).
    pub fn new_as_receiver(
        sender: Address,
        receiver: Address,
        amount: u128,
        preimage: [u8; 32],
        deadline: u32,
    ) -> Self {
        let hash_lock = sha256(&preimage);
        Self {
            payment_id: Self::generate_payment_id(),
            sender,
            receiver,
            amount,
            hash_lock,
            preimage: Some(preimage),
            hops: Vec::new(),
            state: VirtualChannelState::Pending,
            created_at: 0,
            deadline,
        }
    }

    /// Generate a random payment ID.
    pub fn generate_payment_id() -> u128 {
        let bytes = ton_crypto::random_bytes_16();
        u128::from_be_bytes(bytes)
    }

    /// Generate a random preimage for a new payment.
    pub fn generate_preimage() -> [u8; 32] {
        ton_crypto::random_bytes_32()
    }

    /// Add a hop to the payment route.
    ///
    /// Hops must be added in order from sender to receiver.
    /// Each hop's timeout should be less than the previous hop's.
    pub fn add_hop(&mut self, node: Address, channel_id: u128, amount: u128, timeout: u32) -> PaymentResult<()> {
        // Verify timeout decreases along the route
        if let Some(last_hop) = self.hops.last() && timeout >= last_hop.timeout {
            return Err(PaymentError::VirtualChannelError(
                "Hop timeout must decrease along the route".to_string(),
            ));
        }

        // Verify amount is sufficient (accounting for potential fees)
        if amount < self.amount {
            return Err(PaymentError::VirtualChannelError(
                format!("Hop amount {} less than final amount {}", amount, self.amount),
            ));
        }

        self.hops.push(PaymentHop {
            node,
            channel_id,
            amount,
            timeout,
            locked: false,
            settled: false,
        });

        Ok(())
    }

    /// Get the hash lock for this payment.
    pub fn get_hash_lock(&self) -> [u8; 32] {
        self.hash_lock
    }

    /// Get the preimage (only available to receiver or after settlement).
    pub fn get_preimage(&self) -> Option<[u8; 32]> {
        self.preimage
    }

    /// Set the preimage (when received from downstream).
    pub fn set_preimage(&mut self, preimage: [u8; 32]) -> PaymentResult<()> {
        // Verify preimage matches hash lock
        if sha256(&preimage) != self.hash_lock {
            return Err(PaymentError::InvalidPreimage);
        }

        self.preimage = Some(preimage);
        Ok(())
    }

    /// Create conditional payments for each hop.
    ///
    /// Returns a list of conditional payments, one for each hop.
    pub fn create_conditionals(&self) -> Vec<ConditionalPayment> {
        self.hops
            .iter()
            .map(|hop| ConditionalPayment::new(hop.amount, self.hash_lock, hop.timeout))
            .collect()
    }

    /// Mark a hop as locked.
    pub fn mark_hop_locked(&mut self, hop_index: usize) -> PaymentResult<()> {
        let hop = self.hops.get_mut(hop_index)
            .ok_or_else(|| PaymentError::VirtualChannelError(
                format!("Invalid hop index: {}", hop_index),
            ))?;

        hop.locked = true;

        // Check if all hops are locked
        if self.hops.iter().all(|h| h.locked) {
            self.state = VirtualChannelState::Locked;
        }

        Ok(())
    }

    /// Mark a hop as settled.
    pub fn mark_hop_settled(&mut self, hop_index: usize) -> PaymentResult<()> {
        let hop = self.hops.get_mut(hop_index)
            .ok_or_else(|| PaymentError::VirtualChannelError(
                format!("Invalid hop index: {}", hop_index),
            ))?;

        if !hop.locked {
            return Err(PaymentError::VirtualChannelError(
                "Cannot settle unlocked hop".to_string(),
            ));
        }

        hop.settled = true;
        self.state = VirtualChannelState::Settling;

        // Check if all hops are settled
        if self.hops.iter().all(|h| h.settled) {
            self.state = VirtualChannelState::Completed;
        }

        Ok(())
    }

    /// Check if the payment has expired.
    pub fn is_expired(&self, current_time: u32) -> bool {
        current_time >= self.deadline
    }

    /// Cancel the payment (if possible).
    pub fn cancel(&mut self) -> PaymentResult<()> {
        match self.state {
            VirtualChannelState::Pending => {
                self.state = VirtualChannelState::Cancelled;
                Ok(())
            }
            VirtualChannelState::Locked | VirtualChannelState::Settling => {
                Err(PaymentError::VirtualChannelError(
                    "Cannot cancel locked or settling payment".to_string(),
                ))
            }
            VirtualChannelState::Completed | VirtualChannelState::Failed | VirtualChannelState::Cancelled => {
                Err(PaymentError::VirtualChannelError(
                    "Payment already finalized".to_string(),
                ))
            }
        }
    }

    /// Fail the payment (e.g., after timeout).
    pub fn fail(&mut self) {
        if self.state != VirtualChannelState::Completed {
            self.state = VirtualChannelState::Failed;
        }
    }
}

/// Builder for constructing virtual channel payments with routes.
#[derive(Debug)]
pub struct VirtualChannelBuilder {
    sender: Address,
    receiver: Address,
    amount: u128,
    preimage: Option<[u8; 32]>,
    hash_lock: Option<[u8; 32]>,
    deadline: u32,
    hops: Vec<PaymentHop>,
    fee_per_hop: u128,
    timeout_decrement: u32,
}

impl VirtualChannelBuilder {
    /// Create a new builder.
    pub fn new(sender: Address, receiver: Address, amount: u128) -> Self {
        Self {
            sender,
            receiver,
            amount,
            preimage: None,
            hash_lock: None,
            deadline: 0,
            hops: Vec::new(),
            fee_per_hop: 0,
            timeout_decrement: 600, // 10 minutes default
        }
    }

    /// Set the preimage (generates hash_lock automatically).
    pub fn with_preimage(mut self, preimage: [u8; 32]) -> Self {
        self.preimage = Some(preimage);
        self.hash_lock = Some(sha256(&preimage));
        self
    }

    /// Set the hash lock directly (when receiver provides it).
    pub fn with_hash_lock(mut self, hash_lock: [u8; 32]) -> Self {
        self.hash_lock = Some(hash_lock);
        self
    }

    /// Set the final deadline.
    pub fn with_deadline(mut self, deadline: u32) -> Self {
        self.deadline = deadline;
        self
    }

    /// Set the fee per hop.
    pub fn with_fee_per_hop(mut self, fee: u128) -> Self {
        self.fee_per_hop = fee;
        self
    }

    /// Set the timeout decrement per hop.
    pub fn with_timeout_decrement(mut self, decrement: u32) -> Self {
        self.timeout_decrement = decrement;
        self
    }

    /// Add intermediary nodes to the route.
    ///
    /// Automatically calculates amounts (with fees) and timeouts.
    pub fn with_route(mut self, route: Vec<(Address, u128)>) -> Self {
        let num_hops = route.len();
        let mut timeout = self.deadline;

        for (i, (node, channel_id)) in route.into_iter().enumerate() {
            // Amount decreases as we get closer to receiver (fees collected)
            let hops_remaining = num_hops - i;
            let amount = self.amount + self.fee_per_hop * (hops_remaining as u128);

            timeout = timeout.saturating_sub(self.timeout_decrement);

            self.hops.push(PaymentHop {
                node,
                channel_id,
                amount,
                timeout,
                locked: false,
                settled: false,
            });
        }

        self
    }

    /// Build the virtual channel.
    pub fn build(self) -> PaymentResult<VirtualChannel> {
        let hash_lock = self.hash_lock
            .ok_or_else(|| PaymentError::VirtualChannelError("Hash lock not set".to_string()))?;

        let vc = VirtualChannel {
            payment_id: VirtualChannel::generate_payment_id(),
            sender: self.sender,
            receiver: self.receiver,
            amount: self.amount,
            hash_lock,
            preimage: self.preimage,
            hops: self.hops,
            state: VirtualChannelState::Pending,
            created_at: 0,
            deadline: self.deadline,
        };

        // Validate the route
        for (i, hop) in vc.hops.iter().enumerate() {
            if i > 0 && hop.timeout >= vc.hops[i - 1].timeout {
                return Err(PaymentError::VirtualChannelError(
                    "Hop timeouts must decrease along route".to_string(),
                ));
            }
        }

        Ok(vc)
    }
}

/// HTLC (Hash Time-Locked Contract) helper functions.
pub mod htlc {
    use super::*;

    /// Create an HTLC payment request.
    ///
    /// Called by the receiver to initiate receiving a payment.
    pub fn create_payment_request(amount: u128, deadline: u32) -> (HtlcPaymentRequest, [u8; 32]) {
        let preimage = VirtualChannel::generate_preimage();
        let hash_lock = sha256(&preimage);

        let request = HtlcPaymentRequest {
            amount,
            hash_lock,
            deadline,
        };

        (request, preimage)
    }

    /// Verify a preimage against a hash lock.
    pub fn verify_preimage(preimage: &[u8], hash_lock: &[u8; 32]) -> bool {
        sha256(preimage) == *hash_lock
    }
}

/// A payment request containing the hash lock.
#[derive(Debug, Clone)]
pub struct HtlcPaymentRequest {
    /// Amount requested.
    pub amount: u128,

    /// Hash lock (receiver knows preimage).
    pub hash_lock: [u8; 32],

    /// Deadline for the payment.
    pub deadline: u32,
}

impl HtlcPaymentRequest {
    /// Create a conditional payment from this request.
    pub fn to_conditional(&self) -> ConditionalPayment {
        ConditionalPayment::new(self.amount, self.hash_lock, self.deadline)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ton_crypto::Ed25519Keypair;

    fn generate_address() -> Address {
        Ed25519Keypair::generate().public_key
    }

    #[test]
    fn test_virtual_channel_creation() {
        let sender = generate_address();
        let receiver = generate_address();
        let hash_lock = sha256(b"secret");

        let vc = VirtualChannel::new(sender, receiver, 1000, hash_lock, 3600);

        assert_eq!(vc.sender, sender);
        assert_eq!(vc.receiver, receiver);
        assert_eq!(vc.amount, 1000);
        assert_eq!(vc.hash_lock, hash_lock);
        assert_eq!(vc.state, VirtualChannelState::Pending);
    }

    #[test]
    fn test_virtual_channel_as_receiver() {
        let sender = generate_address();
        let receiver = generate_address();
        let preimage = VirtualChannel::generate_preimage();

        let vc = VirtualChannel::new_as_receiver(sender, receiver, 500, preimage, 7200);

        assert_eq!(vc.hash_lock, sha256(&preimage));
        assert_eq!(vc.get_preimage(), Some(preimage));
    }

    #[test]
    fn test_add_hops() {
        let sender = generate_address();
        let receiver = generate_address();
        let intermediate = generate_address();
        let hash_lock = sha256(b"secret");

        let mut vc = VirtualChannel::new(sender, receiver, 1000, hash_lock, 3600);

        // Add first hop with larger timeout
        vc.add_hop(intermediate, 1, 1010, 3000).unwrap();

        // Add second hop with smaller timeout
        vc.add_hop(receiver, 2, 1000, 2400).unwrap();

        assert_eq!(vc.hops.len(), 2);
        assert_eq!(vc.hops[0].timeout, 3000);
        assert_eq!(vc.hops[1].timeout, 2400);
    }

    #[test]
    fn test_add_hops_invalid_timeout() {
        let sender = generate_address();
        let receiver = generate_address();
        let intermediate = generate_address();
        let hash_lock = sha256(b"secret");

        let mut vc = VirtualChannel::new(sender, receiver, 1000, hash_lock, 3600);

        vc.add_hop(intermediate, 1, 1010, 2000).unwrap();

        // Adding hop with larger or equal timeout should fail
        let result = vc.add_hop(receiver, 2, 1000, 2000);
        assert!(result.is_err());

        let result = vc.add_hop(receiver, 2, 1000, 2500);
        assert!(result.is_err());
    }

    #[test]
    fn test_set_preimage() {
        let sender = generate_address();
        let receiver = generate_address();
        let preimage = sha256(b"secret");
        let hash_lock = sha256(&preimage);

        let mut vc = VirtualChannel::new(sender, receiver, 1000, hash_lock, 3600);

        // Set correct preimage
        assert!(vc.set_preimage(preimage).is_ok());
        assert_eq!(vc.get_preimage(), Some(preimage));

        // Wrong preimage should fail
        let mut vc2 = VirtualChannel::new(sender, receiver, 1000, hash_lock, 3600);
        let wrong_preimage = sha256(b"wrong");
        assert!(vc2.set_preimage(wrong_preimage).is_err());
    }

    #[test]
    fn test_create_conditionals() {
        let sender = generate_address();
        let receiver = generate_address();
        let intermediate = generate_address();
        let hash_lock = sha256(b"secret");

        let mut vc = VirtualChannel::new(sender, receiver, 1000, hash_lock, 3600);
        vc.add_hop(intermediate, 1, 1010, 3000).unwrap();
        vc.add_hop(receiver, 2, 1000, 2400).unwrap();

        let conditionals = vc.create_conditionals();

        assert_eq!(conditionals.len(), 2);
        assert_eq!(conditionals[0].amount, 1010);
        assert_eq!(conditionals[0].hash_lock, hash_lock);
        assert_eq!(conditionals[0].deadline, 3000);
        assert_eq!(conditionals[1].amount, 1000);
        assert_eq!(conditionals[1].deadline, 2400);
    }

    #[test]
    fn test_hop_lifecycle() {
        let sender = generate_address();
        let receiver = generate_address();
        let intermediate = generate_address();
        let hash_lock = sha256(b"secret");

        let mut vc = VirtualChannel::new(sender, receiver, 1000, hash_lock, 3600);
        vc.add_hop(intermediate, 1, 1010, 3000).unwrap();
        vc.add_hop(receiver, 2, 1000, 2400).unwrap();

        assert_eq!(vc.state, VirtualChannelState::Pending);

        // Lock first hop
        vc.mark_hop_locked(0).unwrap();
        assert_eq!(vc.state, VirtualChannelState::Pending);

        // Lock second hop - should transition to Locked
        vc.mark_hop_locked(1).unwrap();
        assert_eq!(vc.state, VirtualChannelState::Locked);

        // Settle first hop
        vc.mark_hop_settled(0).unwrap();
        assert_eq!(vc.state, VirtualChannelState::Settling);

        // Settle second hop - should transition to Completed
        vc.mark_hop_settled(1).unwrap();
        assert_eq!(vc.state, VirtualChannelState::Completed);
    }

    #[test]
    fn test_cancel_pending() {
        let sender = generate_address();
        let receiver = generate_address();
        let hash_lock = sha256(b"secret");

        let mut vc = VirtualChannel::new(sender, receiver, 1000, hash_lock, 3600);

        assert!(vc.cancel().is_ok());
        assert_eq!(vc.state, VirtualChannelState::Cancelled);
    }

    #[test]
    fn test_cannot_cancel_locked() {
        let sender = generate_address();
        let receiver = generate_address();
        let hash_lock = sha256(b"secret");

        let mut vc = VirtualChannel::new(sender, receiver, 1000, hash_lock, 3600);
        vc.add_hop(receiver, 1, 1000, 3000).unwrap();
        vc.mark_hop_locked(0).unwrap();

        assert!(vc.cancel().is_err());
    }

    #[test]
    fn test_is_expired() {
        let sender = generate_address();
        let receiver = generate_address();
        let hash_lock = sha256(b"secret");

        let vc = VirtualChannel::new(sender, receiver, 1000, hash_lock, 3600);

        assert!(!vc.is_expired(1000));
        assert!(!vc.is_expired(3599));
        assert!(vc.is_expired(3600));
        assert!(vc.is_expired(5000));
    }

    #[test]
    fn test_builder() {
        let sender = generate_address();
        let receiver = generate_address();
        let intermediate = generate_address();
        let preimage = VirtualChannel::generate_preimage();

        let vc = VirtualChannelBuilder::new(sender, receiver, 1000)
            .with_preimage(preimage)
            .with_deadline(10000)
            .with_fee_per_hop(10)
            .with_timeout_decrement(1000)
            .with_route(vec![
                (intermediate, 1),
                (receiver, 2),
            ])
            .build()
            .unwrap();

        assert_eq!(vc.amount, 1000);
        assert_eq!(vc.hash_lock, sha256(&preimage));
        assert_eq!(vc.hops.len(), 2);
        // First hop has 2 hops remaining, so amount = 1000 + 10*2 = 1020
        assert_eq!(vc.hops[0].amount, 1020);
        // Second hop has 1 hop remaining, so amount = 1000 + 10*1 = 1010
        assert_eq!(vc.hops[1].amount, 1010);
    }

    #[test]
    fn test_htlc_create_payment_request() {
        let (request, preimage) = htlc::create_payment_request(500, 7200);

        assert_eq!(request.amount, 500);
        assert_eq!(request.deadline, 7200);
        assert_eq!(request.hash_lock, sha256(&preimage));
    }

    #[test]
    fn test_htlc_verify_preimage() {
        let preimage = b"my_secret_preimage";
        let hash_lock = sha256(preimage);

        assert!(htlc::verify_preimage(preimage, &hash_lock));
        assert!(!htlc::verify_preimage(b"wrong", &hash_lock));
    }

    #[test]
    fn test_payment_request_to_conditional() {
        let (request, _) = htlc::create_payment_request(1000, 3600);
        let conditional = request.to_conditional();

        assert_eq!(conditional.amount, request.amount);
        assert_eq!(conditional.hash_lock, request.hash_lock);
        assert_eq!(conditional.deadline, request.deadline);
    }
}
