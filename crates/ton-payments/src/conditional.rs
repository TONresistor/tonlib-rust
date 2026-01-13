//! Conditional payments for TON Payment Channels.
//!
//! This module provides generic conditional payments that support arbitrary conditions
//! encoded as TON Cells. This enables:
//! - **HTLC**: Hash Time-Locked Contracts for multi-hop payments
//! - **Multi-sig**: Payments requiring multiple signatures
//! - **Oracle-based**: Payments conditional on oracle attestations
//! - **Custom logic**: Any condition that can be evaluated on-chain
//!
//! # TL-B Schema
//!
//! The official TON TL-B schema uses a generic Cell for conditions:
//! ```tlb
//! cp#_ amount:Coins condition:Cell = ConditionalPayment;
//! ```
//!
//! This allows arbitrary conditions to be encoded and evaluated.

use crate::error::{PaymentError, PaymentResult};
use std::sync::Arc;
use ton_cell::{Cell, CellBuilder, CellSlice};
use ton_crypto::sha256;

/// Condition types for conditional payments (first byte of condition Cell).
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConditionType {
    /// HTLC: Hash Time-Locked Contract
    /// Condition Cell: [type:u8=0x01][hash_lock:256bits][deadline:u32]
    Htlc = 0x01,
    /// Multi-signature requirement
    /// Condition Cell: [type:u8=0x02][threshold:u8][pubkeys:^Cell]
    MultiSig = 0x02,
    /// Oracle attestation
    /// Condition Cell: [type:u8=0x03][oracle_pubkey:256bits][data_hash:256bits]
    Oracle = 0x03,
    /// Custom/arbitrary condition (evaluated by external logic)
    /// Condition Cell: [type:u8=0xFF][custom_data...]
    Custom = 0xFF,
}

impl TryFrom<u8> for ConditionType {
    type Error = PaymentError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x01 => Ok(Self::Htlc),
            0x02 => Ok(Self::MultiSig),
            0x03 => Ok(Self::Oracle),
            0xFF => Ok(Self::Custom),
            _ => Err(PaymentError::InvalidConditional(format!(
                "Unknown condition type: 0x{:02x}",
                value
            ))),
        }
    }
}

/// Trait for evaluating conditions.
///
/// Implement this trait to support custom condition evaluation logic.
pub trait ConditionEvaluator {
    /// Evaluate if a condition is satisfied given a proof.
    ///
    /// # Arguments
    /// * `condition` - The condition Cell to evaluate
    /// * `proof` - The proof data (e.g., preimage for HTLC)
    ///
    /// # Returns
    /// * `Ok(true)` if the condition is satisfied
    /// * `Ok(false)` if the condition is not satisfied
    /// * `Err(...)` if the condition cannot be evaluated
    fn evaluate(&self, condition: &Cell, proof: &[u8]) -> PaymentResult<bool>;
}

/// Default condition evaluator that supports HTLC conditions.
pub struct DefaultConditionEvaluator;

impl ConditionEvaluator for DefaultConditionEvaluator {
    fn evaluate(&self, condition: &Cell, proof: &[u8]) -> PaymentResult<bool> {
        let mut slice = CellSlice::new(condition);

        // Read condition type
        let condition_type = slice
            .load_u8()
            .map_err(|e| PaymentError::CellError(e.to_string()))?;

        match ConditionType::try_from(condition_type)? {
            ConditionType::Htlc => {
                // Load hash_lock (256 bits)
                let hash_bytes = slice
                    .load_bytes(32)
                    .map_err(|e| PaymentError::CellError(e.to_string()))?;

                // Verify preimage
                let computed_hash = sha256(proof);
                Ok(computed_hash == hash_bytes.as_slice())
            }
            ConditionType::MultiSig | ConditionType::Oracle | ConditionType::Custom => {
                // Not implemented in default evaluator
                Err(PaymentError::InvalidConditional(format!(
                    "Condition type {:?} not supported by default evaluator",
                    ConditionType::try_from(condition_type)?
                )))
            }
        }
    }
}

/// A conditional payment with generic condition support.
///
/// According to the official TON TL-B schema:
/// ```tlb
/// cp#_ amount:Coins condition:Cell = ConditionalPayment;
/// ```
///
/// The condition is stored as a generic Cell, enabling arbitrary conditions.
/// For backwards compatibility, HTLC-specific fields are also provided.
#[derive(Debug, Clone)]
pub struct ConditionalPayment {
    /// Amount locked in this conditional payment (in nanotons).
    pub amount: u128,

    /// Generic condition stored as a Cell (official TON format).
    /// This can encode any condition type (HTLC, multi-sig, oracle, etc.)
    pub condition: Cell,

    // ========================================================================
    // Legacy/convenience fields for HTLC compatibility
    // ========================================================================

    /// Hash of the secret preimage (32 bytes) - for HTLC conditions.
    /// This is extracted from the condition Cell for convenience.
    pub hash_lock: [u8; 32],

    /// Deadline (unix timestamp) after which the payment can be reclaimed.
    /// This is extracted from the condition Cell for convenience.
    pub deadline: u32,
}

impl PartialEq for ConditionalPayment {
    fn eq(&self, other: &Self) -> bool {
        self.amount == other.amount
            && self.hash_lock == other.hash_lock
            && self.deadline == other.deadline
    }
}

impl Eq for ConditionalPayment {}

impl ConditionalPayment {
    /// Create a new HTLC conditional payment.
    ///
    /// This is the most common type of conditional payment.
    ///
    /// # Arguments
    /// * `amount` - Amount to lock in the payment
    /// * `hash_lock` - SHA256 hash of the secret preimage
    /// * `deadline` - Unix timestamp after which payment expires
    pub fn new(amount: u128, hash_lock: [u8; 32], deadline: u32) -> Self {
        Self::htlc(amount, hash_lock, deadline)
    }

    /// Create an HTLC (Hash Time-Locked Contract) conditional payment.
    ///
    /// The condition Cell format: [type:u8=0x01][hash_lock:256bits][deadline:u32]
    pub fn htlc(amount: u128, hash_lock: [u8; 32], deadline: u32) -> Self {
        // Build the HTLC condition cell
        let condition = Self::build_htlc_condition(hash_lock, deadline)
            .expect("HTLC condition build should never fail");

        Self {
            amount,
            condition,
            hash_lock,
            deadline,
        }
    }

    /// Build an HTLC condition Cell.
    fn build_htlc_condition(hash_lock: [u8; 32], deadline: u32) -> PaymentResult<Cell> {
        let mut builder = CellBuilder::new();
        builder
            .store_u8(ConditionType::Htlc as u8)
            .map_err(|e| PaymentError::CellError(e.to_string()))?;
        builder
            .store_bytes(&hash_lock)
            .map_err(|e| PaymentError::CellError(e.to_string()))?;
        builder
            .store_u32(deadline)
            .map_err(|e| PaymentError::CellError(e.to_string()))?;
        builder
            .build()
            .map_err(|e| PaymentError::CellError(e.to_string()))
    }

    /// Create a conditional payment with a generic condition Cell.
    ///
    /// This is the most flexible constructor, allowing arbitrary conditions.
    /// Use this for multi-sig, oracle-based, or custom conditions.
    pub fn with_condition(amount: u128, condition: Cell) -> PaymentResult<Self> {
        // Try to extract HTLC fields if this is an HTLC condition
        let (hash_lock, deadline) = Self::extract_htlc_fields(&condition).unwrap_or(([0u8; 32], 0));

        Ok(Self {
            amount,
            condition,
            hash_lock,
            deadline,
        })
    }

    /// Extract HTLC fields from a condition Cell (if it's an HTLC).
    fn extract_htlc_fields(condition: &Cell) -> Option<([u8; 32], u32)> {
        let mut slice = CellSlice::new(condition);

        let condition_type = slice.load_u8().ok()?;
        if condition_type != ConditionType::Htlc as u8 {
            return None;
        }

        let hash_bytes = slice.load_bytes(32).ok()?;
        let mut hash_lock = [0u8; 32];
        hash_lock.copy_from_slice(&hash_bytes);

        let deadline = slice.load_u32().ok()?;

        Some((hash_lock, deadline))
    }

    /// Create a conditional payment from a secret preimage.
    ///
    /// The hash_lock is computed as SHA256(preimage).
    pub fn from_preimage(amount: u128, preimage: &[u8], deadline: u32) -> Self {
        let hash_lock = sha256(preimage);
        Self::htlc(amount, hash_lock, deadline)
    }

    /// Get the condition type.
    pub fn condition_type(&self) -> PaymentResult<ConditionType> {
        let mut slice = CellSlice::new(&self.condition);
        let type_byte = slice
            .load_u8()
            .map_err(|e| PaymentError::CellError(e.to_string()))?;
        ConditionType::try_from(type_byte)
    }

    /// Get a reference to the condition Cell.
    pub fn condition(&self) -> &Cell {
        &self.condition
    }

    /// Evaluate this condition using the provided evaluator and proof.
    pub fn evaluate<E: ConditionEvaluator>(&self, evaluator: &E, proof: &[u8]) -> PaymentResult<bool> {
        evaluator.evaluate(&self.condition, proof)
    }

    /// Evaluate this condition using the default HTLC evaluator.
    pub fn evaluate_htlc(&self, preimage: &[u8]) -> PaymentResult<bool> {
        DefaultConditionEvaluator.evaluate(&self.condition, preimage)
    }

    /// Check if a preimage matches this payment's hash-lock (HTLC compatibility).
    pub fn verify_preimage(&self, preimage: &[u8]) -> bool {
        sha256(preimage) == self.hash_lock
    }

    /// Check if this conditional payment has expired (HTLC compatibility).
    pub fn is_expired(&self, current_time: u32) -> bool {
        current_time >= self.deadline
    }

    /// Serialize the conditional payment.
    ///
    /// Format:
    /// - amount: 16 bytes (big-endian u128)
    /// - hash_lock: 32 bytes
    /// - deadline: 4 bytes (big-endian u32)
    pub fn serialize(&self) -> Vec<u8> {
        let mut data = Vec::with_capacity(52);
        data.extend_from_slice(&self.amount.to_be_bytes());
        data.extend_from_slice(&self.hash_lock);
        data.extend_from_slice(&self.deadline.to_be_bytes());
        data
    }

    /// Deserialize a conditional payment from bytes.
    ///
    /// Returns the payment and number of bytes consumed.
    pub fn deserialize(data: &[u8]) -> PaymentResult<(Self, usize)> {
        if data.len() < 52 {
            return Err(PaymentError::DeserializationError(
                "Data too short for ConditionalPayment".to_string(),
            ));
        }

        let amount = u128::from_be_bytes(data[0..16].try_into().unwrap());

        let mut hash_lock = [0u8; 32];
        hash_lock.copy_from_slice(&data[16..48]);

        let deadline = u32::from_be_bytes(data[48..52].try_into().unwrap());

        Ok((Self::htlc(amount, hash_lock, deadline), 52))
    }

    /// Serialize to a TON Cell for on-chain submission.
    ///
    /// Cell format (official TON TL-B):
    /// ```tlb
    /// cp#_ amount:Coins condition:Cell = ConditionalPayment;
    /// ```
    ///
    /// The condition is stored directly as a Cell (not as a reference).
    pub fn to_cell(&self) -> PaymentResult<Cell> {
        let mut builder = CellBuilder::new();

        // Store amount (Coins format)
        builder
            .store_coins(self.amount)
            .map_err(|e| PaymentError::CellError(e.to_string()))?;

        // Store condition as a reference Cell (official format)
        builder
            .store_ref(Arc::new(self.condition.clone()))
            .map_err(|e| PaymentError::CellError(e.to_string()))?;

        builder
            .build()
            .map_err(|e| PaymentError::CellError(e.to_string()))
    }

    /// Deserialize from a TON Cell.
    ///
    /// Supports both HTLC and generic conditions.
    pub fn from_cell(cell: &Cell) -> PaymentResult<Self> {
        let mut slice = CellSlice::new(cell);

        // Load amount (coins format)
        let amount = slice
            .load_coins()
            .map_err(|e| PaymentError::CellError(e.to_string()))?;

        // Load condition cell
        let condition_cell = slice
            .load_ref()
            .map_err(|e| PaymentError::CellError(e.to_string()))?;

        let condition = condition_cell.clone();

        // Try to extract HTLC fields for backwards compatibility
        let (hash_lock, deadline) = Self::extract_htlc_fields(&condition).unwrap_or(([0u8; 32], 0));

        Ok(Self {
            amount,
            condition,
            hash_lock,
            deadline,
        })
    }
}

/// Builder for creating conditional payments.
///
/// This provides a convenient way to construct conditional payments
/// with various configurations.
#[derive(Debug)]
pub struct ConditionalPaymentBuilder {
    amount: u128,
    hash_lock: Option<[u8; 32]>,
    deadline: u32,
}

impl ConditionalPaymentBuilder {
    /// Create a new builder with the given amount.
    pub fn new(amount: u128) -> Self {
        Self {
            amount,
            hash_lock: None,
            deadline: 0,
        }
    }

    /// Set the hash-lock directly.
    pub fn with_hash_lock(mut self, hash_lock: [u8; 32]) -> Self {
        self.hash_lock = Some(hash_lock);
        self
    }

    /// Set the hash-lock from a preimage.
    pub fn with_preimage(mut self, preimage: &[u8]) -> Self {
        self.hash_lock = Some(sha256(preimage));
        self
    }

    /// Set the deadline (unix timestamp).
    pub fn with_deadline(mut self, deadline: u32) -> Self {
        self.deadline = deadline;
        self
    }

    /// Set the deadline relative to a base time.
    pub fn with_timeout(mut self, base_time: u32, timeout_seconds: u32) -> Self {
        self.deadline = base_time.saturating_add(timeout_seconds);
        self
    }

    /// Build the conditional payment.
    ///
    /// Returns an error if hash_lock is not set.
    pub fn build(self) -> PaymentResult<ConditionalPayment> {
        let hash_lock = self.hash_lock.ok_or_else(|| {
            PaymentError::InvalidConditional("Hash lock not set".to_string())
        })?;

        Ok(ConditionalPayment::htlc(self.amount, hash_lock, self.deadline))
    }
}

/// Generates a random 32-byte preimage for use in hash-locked payments.
pub fn generate_preimage() -> [u8; 32] {
    ton_crypto::random_bytes_32()
}

/// Generates a hash-lock from a preimage.
pub fn hash_preimage(preimage: &[u8]) -> [u8; 32] {
    sha256(preimage)
}

/// A settled conditional payment with the revealed preimage.
#[derive(Debug, Clone)]
pub struct SettledConditional {
    /// The original conditional payment.
    pub payment: ConditionalPayment,

    /// The preimage that was revealed to claim the payment.
    pub preimage: Vec<u8>,
}

impl SettledConditional {
    /// Create a new settled conditional.
    ///
    /// Verifies that the preimage matches the hash-lock.
    pub fn new(payment: ConditionalPayment, preimage: Vec<u8>) -> PaymentResult<Self> {
        if !payment.verify_preimage(&preimage) {
            return Err(PaymentError::InvalidPreimage);
        }

        Ok(Self { payment, preimage })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_conditional_payment_new() {
        let hash_lock = sha256(b"secret");
        let payment = ConditionalPayment::new(1000, hash_lock, 3600);

        assert_eq!(payment.amount, 1000);
        assert_eq!(payment.hash_lock, hash_lock);
        assert_eq!(payment.deadline, 3600);
    }

    #[test]
    fn test_conditional_payment_from_preimage() {
        let preimage = b"my_secret_preimage";
        let payment = ConditionalPayment::from_preimage(500, preimage, 7200);

        assert_eq!(payment.amount, 500);
        assert_eq!(payment.hash_lock, sha256(preimage));
        assert_eq!(payment.deadline, 7200);
    }

    #[test]
    fn test_verify_preimage_correct() {
        let preimage = b"correct_secret";
        let payment = ConditionalPayment::from_preimage(100, preimage, 1000);

        assert!(payment.verify_preimage(preimage));
    }

    #[test]
    fn test_verify_preimage_incorrect() {
        let preimage = b"correct_secret";
        let wrong_preimage = b"wrong_secret";
        let payment = ConditionalPayment::from_preimage(100, preimage, 1000);

        assert!(!payment.verify_preimage(wrong_preimage));
    }

    #[test]
    fn test_is_expired() {
        let payment = ConditionalPayment::new(0, [0u8; 32], 1000);

        assert!(!payment.is_expired(500));
        assert!(!payment.is_expired(999));
        assert!(payment.is_expired(1000));
        assert!(payment.is_expired(1500));
    }

    #[test]
    fn test_serialize_deserialize() {
        let hash_lock = sha256(b"test");
        let payment = ConditionalPayment::new(123456789, hash_lock, 9999);

        let serialized = payment.serialize();
        let (deserialized, consumed) = ConditionalPayment::deserialize(&serialized).unwrap();

        assert_eq!(consumed, 52);
        assert_eq!(payment.amount, deserialized.amount);
        assert_eq!(payment.hash_lock, deserialized.hash_lock);
        assert_eq!(payment.deadline, deserialized.deadline);
    }

    #[test]
    fn test_builder_with_hash_lock() {
        let hash_lock = sha256(b"secret");
        let payment = ConditionalPaymentBuilder::new(1000)
            .with_hash_lock(hash_lock)
            .with_deadline(3600)
            .build()
            .unwrap();

        assert_eq!(payment.amount, 1000);
        assert_eq!(payment.hash_lock, hash_lock);
        assert_eq!(payment.deadline, 3600);
    }

    #[test]
    fn test_builder_with_preimage() {
        let preimage = b"my_preimage";
        let payment = ConditionalPaymentBuilder::new(500)
            .with_preimage(preimage)
            .with_timeout(1000, 3600)
            .build()
            .unwrap();

        assert_eq!(payment.amount, 500);
        assert_eq!(payment.hash_lock, sha256(preimage));
        assert_eq!(payment.deadline, 4600);
    }

    #[test]
    fn test_builder_missing_hash_lock() {
        let result = ConditionalPaymentBuilder::new(100)
            .with_deadline(1000)
            .build();

        assert!(result.is_err());
    }

    #[test]
    fn test_generate_preimage() {
        let preimage1 = generate_preimage();
        let preimage2 = generate_preimage();

        // Preimages should be random and different
        assert_ne!(preimage1, preimage2);
        assert_eq!(preimage1.len(), 32);
    }

    #[test]
    fn test_hash_preimage() {
        let preimage = b"test_preimage";
        let hash = hash_preimage(preimage);

        assert_eq!(hash, sha256(preimage));
    }

    #[test]
    fn test_settled_conditional_valid() {
        let preimage = b"secret";
        let payment = ConditionalPayment::from_preimage(100, preimage, 1000);

        let settled = SettledConditional::new(payment.clone(), preimage.to_vec()).unwrap();

        assert_eq!(settled.payment.amount, 100);
        assert_eq!(settled.preimage, preimage.to_vec());
    }

    #[test]
    fn test_settled_conditional_invalid_preimage() {
        let preimage = b"secret";
        let wrong_preimage = b"wrong";
        let payment = ConditionalPayment::from_preimage(100, preimage, 1000);

        let result = SettledConditional::new(payment, wrong_preimage.to_vec());

        assert!(result.is_err());
        match result {
            Err(PaymentError::InvalidPreimage) => {}
            _ => panic!("Expected InvalidPreimage error"),
        }
    }

    // ========================================================================
    // Cell Serialization Tests
    // ========================================================================

    #[test]
    fn test_conditional_payment_to_cell_from_cell() {
        let hash_lock = sha256(b"secret");
        let payment = ConditionalPayment::new(1_000_000_000, hash_lock, 86400);

        let cell = payment.to_cell().unwrap();
        let deserialized = ConditionalPayment::from_cell(&cell).unwrap();

        assert_eq!(payment.amount, deserialized.amount);
        assert_eq!(payment.hash_lock, deserialized.hash_lock);
        assert_eq!(payment.deadline, deserialized.deadline);
    }

    #[test]
    fn test_conditional_payment_to_cell_from_cell_zero_amount() {
        let hash_lock = sha256(b"zero");
        let payment = ConditionalPayment::new(0, hash_lock, 0);

        let cell = payment.to_cell().unwrap();
        let deserialized = ConditionalPayment::from_cell(&cell).unwrap();

        assert_eq!(payment.amount, deserialized.amount);
        assert_eq!(payment.hash_lock, deserialized.hash_lock);
        assert_eq!(payment.deadline, deserialized.deadline);
    }

    #[test]
    fn test_conditional_payment_to_cell_from_cell_large_amount() {
        let hash_lock = sha256(b"large");
        // Max nanotons in TON supply
        let payment = ConditionalPayment::new(5_000_000_000_000_000_000, hash_lock, u32::MAX);

        let cell = payment.to_cell().unwrap();
        let deserialized = ConditionalPayment::from_cell(&cell).unwrap();

        assert_eq!(payment.amount, deserialized.amount);
        assert_eq!(payment.hash_lock, deserialized.hash_lock);
        assert_eq!(payment.deadline, deserialized.deadline);
    }

    #[test]
    fn test_conditional_payment_to_cell_preserves_preimage_verification() {
        let preimage = b"my_secret_preimage";
        let payment = ConditionalPayment::from_preimage(500, preimage, 3600);

        let cell = payment.to_cell().unwrap();
        let deserialized = ConditionalPayment::from_cell(&cell).unwrap();

        // The deserialized payment should still verify the original preimage
        assert!(deserialized.verify_preimage(preimage));
        assert!(!deserialized.verify_preimage(b"wrong_preimage"));
    }
}
