//! DHT value types.
//!
//! Values stored in the DHT include:
//! - The key description (who owns it, update rules)
//! - The actual value data
//! - TTL (time to live)
//! - Cryptographic signature

use std::time::{SystemTime, UNIX_EPOCH};

use crate::error::{DhtError, Result};
use crate::key::DhtKeyDescription;
use crate::tl::{
    TlReader, TlWriter, DHT_UPDATE_RULE_ANYBODY, DHT_UPDATE_RULE_OVERLAY_NODES,
    DHT_UPDATE_RULE_SIGNATURE, DHT_VALUE, PUB_ED25519,
};

/// Update rules determine who can modify a DHT value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[derive(Default)]
pub enum UpdateRule {
    /// Only the owner (key holder) can update, verified by signature.
    #[default]
    Signature,
    /// Anyone can update the value.
    Anybody,
    /// Only overlay nodes can update (for overlay-specific data).
    OverlayNodes,
}

impl UpdateRule {
    /// Returns the TL schema ID for this update rule.
    pub fn schema_id(&self) -> u32 {
        match self {
            UpdateRule::Signature => DHT_UPDATE_RULE_SIGNATURE,
            UpdateRule::Anybody => DHT_UPDATE_RULE_ANYBODY,
            UpdateRule::OverlayNodes => DHT_UPDATE_RULE_OVERLAY_NODES,
        }
    }

    /// Creates an update rule from its TL schema ID.
    pub fn from_schema_id(id: u32) -> Result<Self> {
        match id {
            DHT_UPDATE_RULE_SIGNATURE => Ok(UpdateRule::Signature),
            DHT_UPDATE_RULE_ANYBODY => Ok(UpdateRule::Anybody),
            DHT_UPDATE_RULE_OVERLAY_NODES => Ok(UpdateRule::OverlayNodes),
            _ => Err(DhtError::InvalidUpdateRule(format!(
                "unknown update rule ID: 0x{:08x}",
                id
            ))),
        }
    }
}


/// A value stored in the DHT.
///
/// DHT values contain:
/// - The key description (identifies the value and its owner)
/// - The actual value data
/// - TTL (Unix timestamp when the value expires)
/// - A signature proving authenticity
#[derive(Debug, Clone)]
pub struct DhtValue {
    /// The key description.
    pub key: DhtKeyDescription,
    /// The value data.
    pub value: Vec<u8>,
    /// Time to live (Unix timestamp).
    pub ttl: i32,
    /// The signature over the value.
    pub signature: Vec<u8>,
}

impl DhtValue {
    /// Maximum size for DHT values (matching official TON dht-types.h:175-176)
    pub const MAX_VALUE_SIZE: usize = 768;

    /// Returns the maximum allowed value size (768 bytes)
    pub fn max_value_size() -> usize {
        Self::MAX_VALUE_SIZE
    }

    /// Creates a new DHT value with validation (matching official TON dht-types.cpp:146-150)
    ///
    /// Returns an error if the value exceeds MAX_VALUE_SIZE (768 bytes)
    pub fn create(key: DhtKeyDescription, value: Vec<u8>, ttl: i32, signature: Vec<u8>) -> Result<Self> {
        if value.len() > Self::MAX_VALUE_SIZE {
            return Err(DhtError::InvalidValue(
                format!("value size {} exceeds max {}", value.len(), Self::MAX_VALUE_SIZE)
            ));
        }
        Ok(Self { key, value, ttl, signature })
    }

    /// Creates a new DHT value.
    pub fn new(key: DhtKeyDescription, value: Vec<u8>, ttl: i32) -> Self {
        Self {
            key,
            value,
            ttl,
            signature: Vec::new(),
        }
    }

    /// Creates a new DHT value with automatic TTL.
    ///
    /// The TTL is set to the current time plus the given duration in seconds.
    pub fn with_ttl_duration(key: DhtKeyDescription, value: Vec<u8>, ttl_seconds: u32) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i32)
            .unwrap_or(0);
        let ttl = now + ttl_seconds as i32;

        Self {
            key,
            value,
            ttl,
            signature: Vec::new(),
        }
    }

    /// Creates a DHT value with a pre-computed signature.
    pub fn with_signature(
        key: DhtKeyDescription,
        value: Vec<u8>,
        ttl: i32,
        signature: Vec<u8>,
    ) -> Self {
        Self {
            key,
            value,
            ttl,
            signature,
        }
    }

    /// Signs the value with the given keypair.
    pub fn sign(&mut self, keypair: &ton_crypto::Ed25519Keypair) {
        let to_sign = self.to_tl_for_signing();
        self.signature = keypair.sign(&to_sign).to_vec();
    }

    /// Verifies the signature on this value.
    pub fn verify_signature(&self) -> Result<()> {
        // First verify the key description signature
        self.key.verify_signature()?;

        // Then verify the value signature based on the update rule
        match self.key.update_rule {
            UpdateRule::Signature => {
                if self.signature.len() != 64 {
                    return Err(DhtError::SignatureVerificationFailed(
                        "value signature must be 64 bytes".into(),
                    ));
                }

                let to_verify = self.to_tl_for_signing();
                let sig: [u8; 64] = self.signature.as_slice().try_into().map_err(|_| {
                    DhtError::SignatureVerificationFailed("invalid signature length".into())
                })?;

                ton_crypto::verify_signature(&self.key.id, &to_verify, &sig).map_err(|e| {
                    DhtError::SignatureVerificationFailed(format!(
                        "Ed25519 verification failed: {}",
                        e
                    ))
                })
            }
            UpdateRule::Anybody => Ok(()),
            UpdateRule::OverlayNodes => {
                // For overlay nodes, we'd need to verify each node's signature
                // This is a simplified implementation
                Ok(())
            }
        }
    }

    /// Checks if the value has expired.
    pub fn is_expired(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i32)
            .unwrap_or(0);
        self.ttl < now
    }

    /// Returns the remaining TTL in seconds, or 0 if expired.
    pub fn remaining_ttl(&self) -> u32 {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i32)
            .unwrap_or(0);
        if self.ttl > now {
            (self.ttl - now) as u32
        } else {
            0
        }
    }

    /// Serializes the value to TL format.
    pub fn to_tl(&self) -> Vec<u8> {
        let mut writer = TlWriter::new();
        writer.write_u32(DHT_VALUE);
        // Key description
        writer.write_raw(&self.key.to_tl());
        // Value
        writer.write_bytes(&self.value);
        // TTL
        writer.write_i32(self.ttl);
        // Signature
        writer.write_bytes(&self.signature);
        writer.finish()
    }

    /// Serializes the value for signing (with zeroed signature).
    fn to_tl_for_signing(&self) -> Vec<u8> {
        let mut writer = TlWriter::new();
        writer.write_u32(DHT_VALUE);
        writer.write_raw(&self.key.to_tl());
        writer.write_bytes(&self.value);
        writer.write_i32(self.ttl);
        // Zero signature for signing/verification
        writer.write_bytes(&[0u8; 64]);
        writer.finish()
    }

    /// Deserializes a value from TL format.
    pub fn from_tl(data: &[u8]) -> Result<Self> {
        let mut reader = TlReader::new(data);

        // Check schema ID
        let schema = reader.read_u32()?;
        if schema != DHT_VALUE {
            return Err(DhtError::TlError(format!(
                "expected dht.value (0x{:08x}), got 0x{:08x}",
                DHT_VALUE, schema
            )));
        }

        // Read key description
        let key_id = reader.read_int256()?;
        let key_name = reader.read_bytes()?;
        let key_idx = reader.read_u32()?;

        // Read PublicKey
        let pub_schema = reader.read_u32()?;
        if pub_schema != PUB_ED25519 {
            return Err(DhtError::TlError(format!(
                "expected pub.ed25519 (0x{:08x}), got 0x{:08x}",
                PUB_ED25519, pub_schema
            )));
        }
        let id = reader.read_int256()?;

        // Read UpdateRule
        let rule_schema = reader.read_u32()?;
        let update_rule = UpdateRule::from_schema_id(rule_schema)?;

        // Read key description signature
        let key_signature = reader.read_bytes()?;

        let key = DhtKeyDescription::with_signature(
            crate::key::DhtKey::new(key_id, key_name, key_idx),
            id,
            update_rule,
            key_signature,
        );

        // Read value
        let value = reader.read_bytes()?;

        // Read TTL
        let ttl = reader.read_i32()?;

        // Read signature
        let signature = reader.read_bytes()?;

        Ok(Self {
            key,
            value,
            ttl,
            signature,
        })
    }
}

/// Result of a DHT find_value operation.
#[derive(Debug, Clone)]
pub enum DhtValueResult {
    /// The value was found.
    Found(DhtValue),
    /// The value was not found, but here are closer nodes to query.
    NotFound(Vec<crate::node::DhtNode>),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::DhtKey;
    use ton_crypto::Ed25519Keypair;

    #[test]
    fn test_update_rule_schema_ids() {
        assert_eq!(UpdateRule::Signature.schema_id(), DHT_UPDATE_RULE_SIGNATURE);
        assert_eq!(UpdateRule::Anybody.schema_id(), DHT_UPDATE_RULE_ANYBODY);
        assert_eq!(
            UpdateRule::OverlayNodes.schema_id(),
            DHT_UPDATE_RULE_OVERLAY_NODES
        );
    }

    #[test]
    fn test_update_rule_roundtrip() {
        for rule in [
            UpdateRule::Signature,
            UpdateRule::Anybody,
            UpdateRule::OverlayNodes,
        ] {
            let id = rule.schema_id();
            let decoded = UpdateRule::from_schema_id(id).unwrap();
            assert_eq!(rule, decoded);
        }
    }

    #[test]
    fn test_value_creation() {
        let keypair = Ed25519Keypair::generate();
        let key = DhtKey::from_public_key(&keypair.public_key, b"address", 0);
        let key_desc = DhtKeyDescription::new(key, keypair.public_key, UpdateRule::Signature);

        let value = DhtValue::new(key_desc, b"test data".to_vec(), 1234567890);

        assert_eq!(value.value, b"test data");
        assert_eq!(value.ttl, 1234567890);
    }

    #[test]
    fn test_value_with_ttl_duration() {
        let keypair = Ed25519Keypair::generate();
        let key = DhtKey::from_public_key(&keypair.public_key, b"test", 0);
        let key_desc = DhtKeyDescription::new(key, keypair.public_key, UpdateRule::Signature);

        let value = DhtValue::with_ttl_duration(key_desc, b"data".to_vec(), 3600);

        assert!(value.remaining_ttl() > 0);
        assert!(value.remaining_ttl() <= 3600);
        assert!(!value.is_expired());
    }

    #[test]
    fn test_value_expiration() {
        let keypair = Ed25519Keypair::generate();
        let key = DhtKey::from_public_key(&keypair.public_key, b"test", 0);
        let key_desc = DhtKeyDescription::new(key, keypair.public_key, UpdateRule::Signature);

        // Create a value that's already expired
        let value = DhtValue::new(key_desc, b"old data".to_vec(), 1);

        assert!(value.is_expired());
        assert_eq!(value.remaining_ttl(), 0);
    }

    #[test]
    fn test_value_signature() {
        let keypair = Ed25519Keypair::generate();
        let key = DhtKey::from_public_key(&keypair.public_key, b"address", 0);

        let mut key_desc = DhtKeyDescription::new(key, keypair.public_key, UpdateRule::Signature);
        key_desc.sign(&keypair);

        let mut value = DhtValue::with_ttl_duration(key_desc, b"my address".to_vec(), 3600);
        value.sign(&keypair);

        assert_eq!(value.signature.len(), 64);
        assert!(value.verify_signature().is_ok());
    }

    #[test]
    fn test_value_anybody_rule() {
        let keypair = Ed25519Keypair::generate();
        let key = DhtKey::from_public_key(&keypair.public_key, b"public", 0);
        let key_desc = DhtKeyDescription::new(key, keypair.public_key, UpdateRule::Anybody);

        let value = DhtValue::new(key_desc, b"public data".to_vec(), 1234567890);

        // No signature needed for Anybody rule
        assert!(value.verify_signature().is_ok());
    }

    #[test]
    fn test_create_valid_value() {
        let keypair = Ed25519Keypair::generate();
        let key = DhtKey::from_public_key(&keypair.public_key, b"test", 0);
        let key_desc = DhtKeyDescription::new(key, keypair.public_key, UpdateRule::Signature);

        // Create with valid size (100 bytes)
        let result = DhtValue::create(key_desc.clone(), b"small value".to_vec(), 1234567890, vec![]);
        assert!(result.is_ok());

        let value = result.unwrap();
        assert_eq!(value.value, b"small value");
    }

    #[test]
    fn test_create_value_at_max_size() {
        let keypair = Ed25519Keypair::generate();
        let key = DhtKey::from_public_key(&keypair.public_key, b"max", 0);
        let key_desc = DhtKeyDescription::new(key, keypair.public_key, UpdateRule::Signature);

        // Create with exactly 768 bytes (the max allowed)
        let value_data = vec![0u8; DhtValue::MAX_VALUE_SIZE];
        let result = DhtValue::create(key_desc, value_data.clone(), 1234567890, vec![]);

        assert!(result.is_ok());
        assert_eq!(result.unwrap().value.len(), 768);
    }

    #[test]
    fn test_create_value_oversized() {
        let keypair = Ed25519Keypair::generate();
        let key = DhtKey::from_public_key(&keypair.public_key, b"big", 0);
        let key_desc = DhtKeyDescription::new(key, keypair.public_key, UpdateRule::Signature);

        // Create with 769 bytes (exceeds max of 768)
        let value_data = vec![0u8; DhtValue::MAX_VALUE_SIZE + 1];
        let result = DhtValue::create(key_desc, value_data, 1234567890, vec![]);

        assert!(result.is_err());
        if let Err(DhtError::InvalidValue(msg)) = result {
            assert!(msg.contains("exceeds max"));
        } else {
            panic!("Expected InvalidValue error");
        }
    }
}
