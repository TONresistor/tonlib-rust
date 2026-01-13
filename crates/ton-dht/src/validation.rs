//! Value validation module for DHT security.
//!
//! This module provides comprehensive validation for DHT values to ensure:
//! - Cryptographic signatures are correct
//! - Values don't exceed size limits
//! - TTL is reasonable and not expired
//! - Key descriptions are properly signed

use std::time::{SystemTime, UNIX_EPOCH};

use crate::error::{DhtError, Result};
use crate::value::DhtValue;

#[cfg(debug_assertions)]
use tracing::debug;

/// Validates incoming DHT values for security and conformity.
///
/// This validator ensures:
/// 1. Values don't exceed maximum size (768 bytes)
/// 2. Key description signatures are valid
/// 3. Value signatures are verified based on update rule
/// 4. TTL is reasonable (not too far in the future, not expired)
#[derive(Debug, Clone)]
pub struct ValueValidator {
    /// Maximum allowed value size in bytes.
    max_value_size: usize,
    /// Maximum allowed TTL in seconds from now (30 days).
    max_ttl_future: u32,
}

impl ValueValidator {
    /// Maximum value size (matching TON specification: 768 bytes).
    pub const DEFAULT_MAX_SIZE: usize = 768;

    /// Maximum TTL into the future (1 hour + 60s margin, matching official TON).
    /// Reference: ton-blockchain/ton/dht/dht.cpp - values with TTL > now + 3660 are rejected
    pub const DEFAULT_MAX_TTL_FUTURE: u32 = 3660;

    /// Creates a new value validator with default configuration.
    pub fn new() -> Self {
        Self {
            max_value_size: Self::DEFAULT_MAX_SIZE,
            max_ttl_future: Self::DEFAULT_MAX_TTL_FUTURE,
        }
    }

    /// Creates a new value validator with custom configuration.
    pub fn with_config(max_value_size: usize, max_ttl_future: u32) -> Self {
        Self {
            max_value_size,
            max_ttl_future,
        }
    }

    /// Validates an incoming DHT value.
    ///
    /// This performs comprehensive validation:
    /// 1. Checks value size limit
    /// 2. Verifies key description signature
    /// 3. Verifies value signature based on update rule
    /// 4. Validates TTL
    ///
    /// Returns an error if any validation fails.
    pub fn validate_incoming_value(&self, value: &DhtValue) -> Result<()> {
        // Step 1: Check size limit
        self.validate_value_size(value)?;

        // Step 2: Verify key description signature
        value.key.verify_signature()?;

        // Step 3: Verify value signature based on update rule
        value.verify_signature()?;

        // Step 4: Validate TTL
        self.validate_ttl(value)?;

        #[cfg(debug_assertions)]
        debug!(
            "Value validation passed: key={}, ttl={}, size={}",
            hex::encode(&value.key.key.id[..8]),
            value.ttl,
            value.value.len()
        );

        Ok(())
    }

    /// Validates value size doesn't exceed maximum.
    fn validate_value_size(&self, value: &DhtValue) -> Result<()> {
        if value.value.len() > self.max_value_size {
            return Err(DhtError::InvalidValue(format!(
                "value size {} exceeds maximum {}",
                value.value.len(),
                self.max_value_size
            )));
        }
        Ok(())
    }

    /// Validates that TTL is reasonable.
    ///
    /// Checks:
    /// - TTL is not expired (ttl > now)
    /// - TTL is not too far in the future (ttl <= now + 30 days)
    fn validate_ttl(&self, value: &DhtValue) -> Result<()> {
        let now = Self::current_timestamp()?;

        // Check if value is already expired
        if value.ttl <= now {
            return Err(DhtError::ValueExpired);
        }

        // Check if TTL is too far in the future
        let ttl_seconds = value.ttl - now;
        if ttl_seconds > self.max_ttl_future as i32 {
            return Err(DhtError::InvalidValue(format!(
                "TTL {} seconds is too far in future (max: {})",
                ttl_seconds, self.max_ttl_future
            )));
        }

        Ok(())
    }

    /// Gets the current Unix timestamp.
    fn current_timestamp() -> Result<i32> {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i32)
            .map_err(|e| DhtError::CryptoError(format!("failed to get current time: {}", e)))
    }
}

impl Default for ValueValidator {
    fn default() -> Self {
        Self::new()
    }
}

/// Hex encoding helper (for debugging).
#[cfg(debug_assertions)]
mod hex {
    pub fn encode(data: &[u8]) -> String {
        data.iter().map(|b| format!("{:02x}", b)).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::DhtKey;
    use crate::value::UpdateRule;
    use ton_crypto::Ed25519Keypair;

    fn create_test_value(keypair: &Ed25519Keypair, ttl: i32) -> DhtValue {
        let key = DhtKey::from_public_key(&keypair.public_key, b"test", 0);
        let mut key_desc =
            crate::key::DhtKeyDescription::new(key, keypair.public_key, UpdateRule::Signature);
        key_desc.sign(keypair);

        let mut value = DhtValue::new(key_desc, b"test data".to_vec(), ttl);
        value.sign(keypair);
        value
    }

    #[test]
    fn test_validator_creation() {
        let validator = ValueValidator::new();
        assert_eq!(validator.max_value_size, 768);
        assert_eq!(validator.max_ttl_future, 3660); // 1 hour + 60s margin per official TON
    }

    #[test]
    fn test_validator_with_custom_config() {
        let validator = ValueValidator::with_config(512, 7 * 24 * 60 * 60);
        assert_eq!(validator.max_value_size, 512);
        assert_eq!(validator.max_ttl_future, 7 * 24 * 60 * 60);
    }

    #[test]
    fn test_validate_valid_value() {
        let keypair = Ed25519Keypair::generate();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i32;
        let ttl = now + 3600; // 1 hour from now

        let value = create_test_value(&keypair, ttl);
        let validator = ValueValidator::new();

        assert!(validator.validate_incoming_value(&value).is_ok());
    }

    #[test]
    fn test_validate_expired_value() {
        let keypair = Ed25519Keypair::generate();
        let ttl = 1; // Already expired (timestamp 1 second since epoch)

        let value = create_test_value(&keypair, ttl);
        let validator = ValueValidator::new();

        let result = validator.validate_incoming_value(&value);
        assert!(result.is_err());
        if let Err(DhtError::ValueExpired) = result {
            // Expected
        } else {
            panic!("Expected ValueExpired error");
        }
    }

    #[test]
    fn test_validate_ttl_too_far_future() {
        let keypair = Ed25519Keypair::generate();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i32;
        // Set TTL to 2 hours in the future (exceeds 1 hour + margin limit)
        let ttl = now + 7200;

        let value = create_test_value(&keypair, ttl);
        let validator = ValueValidator::new();

        let result = validator.validate_incoming_value(&value);
        assert!(result.is_err());
        if let Err(DhtError::InvalidValue(msg)) = result {
            assert!(msg.contains("too far in future"));
        } else {
            panic!("Expected InvalidValue error");
        }
    }

    #[test]
    fn test_validate_ttl_boundary_valid() {
        let keypair = Ed25519Keypair::generate();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i32;
        // Set TTL exactly to 3660s limit (1 hour + 60s margin per official TON)
        let ttl = now + 3660;

        let value = create_test_value(&keypair, ttl);
        let validator = ValueValidator::new();

        assert!(validator.validate_incoming_value(&value).is_ok());
    }

    #[test]
    fn test_validate_oversized_value() {
        let keypair = Ed25519Keypair::generate();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i32;
        let ttl = now + 3600;

        let key = DhtKey::from_public_key(&keypair.public_key, b"big", 0);
        let mut key_desc =
            crate::key::DhtKeyDescription::new(key, keypair.public_key, UpdateRule::Signature);
        key_desc.sign(&keypair);

        // Create oversized value (769 bytes, exceeds 768 limit)
        let oversized_data = vec![0u8; 769];
        let mut value = DhtValue::new(key_desc, oversized_data, ttl);
        value.sign(&keypair);

        let validator = ValueValidator::new();
        let result = validator.validate_incoming_value(&value);
        assert!(result.is_err());
        if let Err(DhtError::InvalidValue(msg)) = result {
            assert!(msg.contains("exceeds maximum"));
        } else {
            panic!("Expected InvalidValue error");
        }
    }

    #[test]
    fn test_validate_custom_max_size() {
        let keypair = Ed25519Keypair::generate();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i32;
        let ttl = now + 3600;

        let key = DhtKey::from_public_key(&keypair.public_key, b"test", 0);
        let mut key_desc =
            crate::key::DhtKeyDescription::new(key, keypair.public_key, UpdateRule::Signature);
        key_desc.sign(&keypair);

        // Create value with 512 bytes (valid for default, but we'll test with smaller limit)
        let data = vec![0u8; 512];
        let mut value = DhtValue::new(key_desc, data, ttl);
        value.sign(&keypair);

        // Should pass with default validator (768 byte limit)
        let validator_default = ValueValidator::new();
        assert!(validator_default.validate_incoming_value(&value).is_ok());

        // Should fail with custom validator (256 byte limit)
        let validator_strict = ValueValidator::with_config(256, 30 * 24 * 60 * 60);
        let result = validator_strict.validate_incoming_value(&value);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_anybody_rule_no_signature() {
        let keypair = Ed25519Keypair::generate();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i32;
        let ttl = now + 3600;

        let key = DhtKey::from_public_key(&keypair.public_key, b"public", 0);
        let key_desc =
            crate::key::DhtKeyDescription::new(key, keypair.public_key, UpdateRule::Anybody);

        // For Anybody rule, no signature is needed
        let value = DhtValue::new(key_desc, b"public data".to_vec(), ttl);

        let validator = ValueValidator::new();
        assert!(validator.validate_incoming_value(&value).is_ok());
    }

    #[test]
    fn test_validate_corrupted_signature() {
        let keypair = Ed25519Keypair::generate();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i32;
        let ttl = now + 3600;

        let key = DhtKey::from_public_key(&keypair.public_key, b"test", 0);
        let mut key_desc =
            crate::key::DhtKeyDescription::new(key, keypair.public_key, UpdateRule::Signature);
        key_desc.sign(&keypair);

        let mut value = DhtValue::new(key_desc, b"test data".to_vec(), ttl);
        value.sign(&keypair);

        // Corrupt the signature
        if !value.signature.is_empty() {
            value.signature[0] ^= 0xFF; // Flip bits in first byte
        }

        let validator = ValueValidator::new();
        let result = validator.validate_incoming_value(&value);
        assert!(result.is_err());
    }

    #[test]
    fn test_default_validator() {
        let validator1 = ValueValidator::default();
        let validator2 = ValueValidator::new();

        assert_eq!(validator1.max_value_size, validator2.max_value_size);
        assert_eq!(validator1.max_ttl_future, validator2.max_ttl_future);
    }
}
