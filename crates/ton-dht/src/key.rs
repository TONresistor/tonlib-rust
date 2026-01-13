//! DHT key types.
//!
//! DHT keys identify values stored in the distributed hash table.
//! A key consists of:
//! - A 256-bit key ID (hash of the key description)
//! - A name (e.g., "address", "nodes")
//! - An index (for multiple values under the same name)
//!
//! Keys are described using `DhtKeyDescription` which includes the update rule
//! and cryptographic verification information.

use ton_crypto::sha256::sha256;

use crate::error::{DhtError, Result};
use crate::tl::{TlReader, TlWriter, DHT_KEY, PUB_ED25519};
use crate::value::UpdateRule;

/// Common key names used in TON DHT.
pub mod key_names {
    /// ADNL address resolution key.
    pub const ADDRESS: &[u8] = b"address";
    /// Overlay network nodes key.
    pub const NODES: &[u8] = b"nodes";
    /// TON blockchain nodes key.
    pub const TON_NODES: &[u8] = b"ton-nodes";
}

/// A DHT key identifying a value in the hash table.
///
/// The key consists of:
/// - `id`: 256-bit hash of the serialized key description
/// - `name`: Human-readable name (e.g., "address")
/// - `idx`: Index for multiple values under the same name (0-15, matching official TON td::uint32)
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DhtKey {
    /// The 256-bit key ID (hash).
    pub id: [u8; 32],
    /// The key name (e.g., "address", "nodes").
    pub name: Vec<u8>,
    /// The key index (for multiple values), max 15 (matching official TON dht-types.h:111)
    pub idx: u32,
}

impl DhtKey {
    /// Maximum length for DHT key names (matching official TON dht-types.h:84-85)
    pub const MAX_NAME_LENGTH: usize = 127;
    /// Maximum value for DHT key index (matching official TON dht-types.h:87-88)
    pub const MAX_INDEX: u32 = 15;

    /// Creates a new DHT key with validation (matching official TON dht-types.cpp:32-44)
    ///
    /// Returns an error if:
    /// - name is empty or longer than 127 bytes
    /// - idx exceeds 15
    pub fn create(id: [u8; 32], name: Vec<u8>, idx: u32) -> Result<Self> {
        if name.len() > Self::MAX_NAME_LENGTH {
            return Err(DhtError::InvalidKey(
                format!("name length {} exceeds max {}", name.len(), Self::MAX_NAME_LENGTH)
            ));
        }
        if name.is_empty() {
            return Err(DhtError::InvalidKey("empty key name".to_string()));
        }
        if idx > Self::MAX_INDEX {
            return Err(DhtError::InvalidKey(
                format!("key index {} exceeds max {}", idx, Self::MAX_INDEX)
            ));
        }
        Ok(Self { id, name, idx })
    }

    /// Creates a new DHT key.
    pub fn new(id: [u8; 32], name: Vec<u8>, idx: u32) -> Self {
        Self { id, name, idx }
    }

    /// Creates a DHT key from a public key and name.
    ///
    /// The key ID is calculated as: SHA256(id_hash || name || idx)
    /// where id_hash is the SHA256 of the TL-serialized public key.
    pub fn from_public_key(public_key: &[u8; 32], name: &[u8], idx: u32) -> Self {
        // Calculate the public key hash (TL-serialized)
        let mut tl = TlWriter::new();
        tl.write_u32(PUB_ED25519);
        tl.write_int256(public_key);
        let id_hash = sha256(&tl.finish());

        // Calculate the key ID
        let mut key_tl = TlWriter::new();
        key_tl.write_u32(DHT_KEY);
        key_tl.write_int256(&id_hash);
        key_tl.write_bytes(name);
        key_tl.write_u32(idx);
        let key_id = sha256(&key_tl.finish());

        Self {
            id: key_id,
            name: name.to_vec(),
            idx,
        }
    }

    /// Creates a DHT key for an ADNL address.
    pub fn for_address(public_key: &[u8; 32]) -> Self {
        Self::from_public_key(public_key, key_names::ADDRESS, 0)
    }

    /// Creates a DHT key for overlay nodes.
    pub fn for_nodes(overlay_id: &[u8; 32]) -> Self {
        Self::from_public_key(overlay_id, key_names::NODES, 0)
    }

    /// Serializes the key to TL format.
    pub fn to_tl(&self) -> Vec<u8> {
        let mut writer = TlWriter::new();
        writer.write_int256(&self.id);
        writer.write_bytes(&self.name);
        writer.write_u32(self.idx);
        writer.finish()
    }

    /// Deserializes a key from TL format.
    pub fn from_tl(data: &[u8]) -> Result<Self> {
        let mut reader = TlReader::new(data);
        let id = reader.read_int256()?;
        let name = reader.read_bytes()?;
        let idx = reader.read_u32()?;
        Ok(Self { id, name, idx })
    }
}

/// A full DHT key description including verification information.
///
/// The key description contains:
/// - The key itself
/// - The owner's public key (for signature verification)
/// - The update rule (who can update the value)
/// - A signature proving ownership
#[derive(Debug, Clone)]
pub struct DhtKeyDescription {
    /// The DHT key.
    pub key: DhtKey,
    /// The owner's public key (Ed25519).
    pub id: [u8; 32],
    /// The update rule.
    pub update_rule: UpdateRule,
    /// The signature over the key description.
    pub signature: Vec<u8>,
}

impl DhtKeyDescription {
    /// Creates a new key description.
    pub fn new(key: DhtKey, id: [u8; 32], update_rule: UpdateRule) -> Self {
        Self {
            key,
            id,
            update_rule,
            signature: Vec::new(),
        }
    }

    /// Creates a key description with a signature.
    pub fn with_signature(
        key: DhtKey,
        id: [u8; 32],
        update_rule: UpdateRule,
        signature: Vec<u8>,
    ) -> Self {
        Self {
            key,
            id,
            update_rule,
            signature,
        }
    }

    /// Signs the key description with the given keypair.
    pub fn sign(&mut self, keypair: &ton_crypto::Ed25519Keypair) {
        // Create version with zeroed signature for signing
        let to_sign = self.to_tl_for_signing();
        self.signature = keypair.sign(&to_sign).to_vec();
    }

    /// Verifies the signature on this key description.
    pub fn verify_signature(&self) -> Result<()> {
        if self.update_rule == UpdateRule::Anybody {
            return Ok(());
        }

        if self.signature.len() != 64 {
            return Err(DhtError::SignatureVerificationFailed(
                "signature must be 64 bytes".into(),
            ));
        }

        let to_verify = self.to_tl_for_signing();
        let sig: [u8; 64] = self.signature.as_slice().try_into().map_err(|_| {
            DhtError::SignatureVerificationFailed("invalid signature length".into())
        })?;

        ton_crypto::verify_signature(&self.id, &to_verify, &sig).map_err(|e| {
            DhtError::SignatureVerificationFailed(format!("Ed25519 verification failed: {}", e))
        })
    }

    /// Serializes the key description to TL format.
    pub fn to_tl(&self) -> Vec<u8> {
        let mut writer = TlWriter::new();
        // dht.keyDescription key:dht.key id:PublicKey update_rule:dht.UpdateRule signature:bytes
        writer.write_raw(&self.key.to_tl());
        // PublicKey (pub.ed25519)
        writer.write_u32(PUB_ED25519);
        writer.write_int256(&self.id);
        // UpdateRule
        writer.write_u32(self.update_rule.schema_id());
        // Signature
        writer.write_bytes(&self.signature);
        writer.finish()
    }

    /// Serializes the key description for signing (with zeroed signature).
    fn to_tl_for_signing(&self) -> Vec<u8> {
        let mut writer = TlWriter::new();
        writer.write_raw(&self.key.to_tl());
        writer.write_u32(PUB_ED25519);
        writer.write_int256(&self.id);
        writer.write_u32(self.update_rule.schema_id());
        // Zero signature for signing/verification
        writer.write_bytes(&[0u8; 64]);
        writer.finish()
    }

    /// Deserializes a key description from TL format.
    pub fn from_tl(data: &[u8]) -> Result<Self> {
        let mut reader = TlReader::new(data);

        // Read key
        let key_id = reader.read_int256()?;
        let key_name = reader.read_bytes()?;
        let key_idx = reader.read_u32()?;
        let key = DhtKey::new(key_id, key_name, key_idx);

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

        // Read signature
        let signature = reader.read_bytes()?;

        Ok(Self {
            key,
            id,
            update_rule,
            signature,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ton_crypto::Ed25519Keypair;

    #[test]
    fn test_key_creation() {
        let keypair = Ed25519Keypair::generate();
        let key = DhtKey::from_public_key(&keypair.public_key, b"address", 0);

        assert_eq!(key.name, b"address");
        assert_eq!(key.idx, 0);
        assert_eq!(key.id.len(), 32);
    }

    #[test]
    fn test_key_for_address() {
        let keypair = Ed25519Keypair::generate();
        let key = DhtKey::for_address(&keypair.public_key);

        assert_eq!(key.name, b"address");
        assert_eq!(key.idx, 0);
    }

    #[test]
    fn test_key_serialization() {
        let keypair = Ed25519Keypair::generate();
        let key = DhtKey::from_public_key(&keypair.public_key, b"test", 42);

        let tl = key.to_tl();
        let decoded = DhtKey::from_tl(&tl).unwrap();

        assert_eq!(key.id, decoded.id);
        assert_eq!(key.name, decoded.name);
        assert_eq!(key.idx, decoded.idx);
    }

    #[test]
    fn test_key_description_signature() {
        let keypair = Ed25519Keypair::generate();
        let key = DhtKey::from_public_key(&keypair.public_key, b"address", 0);

        let mut desc = DhtKeyDescription::new(key, keypair.public_key, UpdateRule::Signature);
        desc.sign(&keypair);

        assert_eq!(desc.signature.len(), 64);
        assert!(desc.verify_signature().is_ok());
    }

    #[test]
    fn test_key_description_anybody() {
        let keypair = Ed25519Keypair::generate();
        let key = DhtKey::from_public_key(&keypair.public_key, b"test", 0);

        let desc = DhtKeyDescription::new(key, keypair.public_key, UpdateRule::Anybody);
        assert!(desc.verify_signature().is_ok());
    }

    #[test]
    fn test_create_valid_key() {
        let id = [0u8; 32];
        let name = b"address".to_vec();

        let result = DhtKey::create(id, name.clone(), 0);
        assert!(result.is_ok());

        let key = result.unwrap();
        assert_eq!(key.id, id);
        assert_eq!(key.name, name);
        assert_eq!(key.idx, 0);
    }

    #[test]
    fn test_create_key_empty_name() {
        let id = [0u8; 32];
        let name = vec![];

        let result = DhtKey::create(id, name, 0);
        assert!(result.is_err());

        if let Err(DhtError::InvalidKey(msg)) = result {
            assert!(msg.contains("empty"));
        } else {
            panic!("Expected InvalidKey error");
        }
    }

    #[test]
    fn test_create_key_name_too_long() {
        let id = [0u8; 32];
        // Create a name longer than 127 bytes
        let name = vec![b'x'; DhtKey::MAX_NAME_LENGTH + 1];

        let result = DhtKey::create(id, name, 0);
        assert!(result.is_err());

        if let Err(DhtError::InvalidKey(msg)) = result {
            assert!(msg.contains("exceeds max"));
        } else {
            panic!("Expected InvalidKey error");
        }
    }

    #[test]
    fn test_create_key_index_too_high() {
        let id = [0u8; 32];
        let name = b"test".to_vec();
        // Try idx 16, which exceeds the max of 15
        let result = DhtKey::create(id, name, DhtKey::MAX_INDEX + 1);

        assert!(result.is_err());

        if let Err(DhtError::InvalidKey(msg)) = result {
            assert!(msg.contains("exceeds max"));
        } else {
            panic!("Expected InvalidKey error");
        }
    }

    #[test]
    fn test_create_key_max_index_valid() {
        let id = [0u8; 32];
        let name = b"test".to_vec();
        // idx=15 should be valid (max allowed)
        let result = DhtKey::create(id, name.clone(), DhtKey::MAX_INDEX);

        assert!(result.is_ok());
        assert_eq!(result.unwrap().idx, 15);
    }

    #[test]
    fn test_create_key_max_name_length_valid() {
        let id = [0u8; 32];
        // Create a name with exactly 127 bytes (max allowed)
        let name = vec![b'a'; DhtKey::MAX_NAME_LENGTH];

        let result = DhtKey::create(id, name.clone(), 0);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().name.len(), 127);
    }
}
