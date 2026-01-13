//! Key ID calculation for TON.
//!
//! This module provides key ID calculation used throughout TON,
//! particularly for ADNL addresses. A key ID is calculated as the
//! SHA256 hash of the TL-serialized public key.

use crate::sha256::sha256;

/// TL prefix for pub.ed25519 schema.
///
/// This is the CRC32 of the TL schema "pub.ed25519 key:int256 = PublicKey".
/// Used in little-endian byte order: [0x4813b4c6] -> [0xC6, 0xB4, 0x13, 0x48]
pub const TL_PREFIX_ED25519: [u8; 4] = [0xC6, 0xB4, 0x13, 0x48];

/// TL prefix for pub.aes schema.
///
/// This is the CRC32 of the TL schema "pub.aes key:int256 = PublicKey".
pub const TL_PREFIX_AES: [u8; 4] = [0x2A, 0x28, 0x6D, 0xD7];

/// TL prefix for pub.overlay schema.
///
/// This is the CRC32 of the TL schema "pub.overlay name:bytes = PublicKey".
pub const TL_PREFIX_OVERLAY: [u8; 4] = [0xC3, 0x0B, 0x54, 0xB1];

/// Calculate the key ID for an Ed25519 public key.
///
/// The key ID is calculated as:
/// `SHA256(TL_PREFIX_ED25519 || public_key)`
///
/// This is used as the ADNL address for a node.
///
/// # Arguments
/// * `public_key` - A 32-byte Ed25519 public key
///
/// # Returns
/// A 32-byte key ID
///
/// # Example
/// ```
/// use ton_crypto::keys::calculate_key_id;
/// use ton_crypto::ed25519::Ed25519Keypair;
///
/// let keypair = Ed25519Keypair::generate();
/// let key_id = calculate_key_id(&keypair.public_key);
///
/// // The key ID is used as the ADNL address
/// assert_eq!(key_id.len(), 32);
/// ```
pub fn calculate_key_id(public_key: &[u8; 32]) -> [u8; 32] {
    let mut data = Vec::with_capacity(4 + 32);
    data.extend_from_slice(&TL_PREFIX_ED25519);
    data.extend_from_slice(public_key);
    sha256(&data)
}

/// Calculate the key ID for a public key with a custom TL prefix.
///
/// # Arguments
/// * `tl_prefix` - The 4-byte TL schema ID
/// * `key_data` - The key data to hash
///
/// # Returns
/// A 32-byte key ID
pub fn calculate_key_id_with_prefix(tl_prefix: &[u8; 4], key_data: &[u8]) -> [u8; 32] {
    let mut data = Vec::with_capacity(4 + key_data.len());
    data.extend_from_slice(tl_prefix);
    data.extend_from_slice(key_data);
    sha256(&data)
}

/// Calculate the key ID for an AES key.
///
/// # Arguments
/// * `key` - A 32-byte AES key
///
/// # Returns
/// A 32-byte key ID
pub fn calculate_aes_key_id(key: &[u8; 32]) -> [u8; 32] {
    calculate_key_id_with_prefix(&TL_PREFIX_AES, key)
}

/// Calculate an overlay ID from overlay name.
///
/// # Arguments
/// * `name` - The overlay name (typically a workchain ID and shard)
///
/// # Returns
/// A 32-byte overlay ID
pub fn calculate_overlay_id(name: &[u8]) -> [u8; 32] {
    // For overlay, the name is TL-serialized as bytes (length-prefixed)
    // But for simple cases, we just hash the prefix + name
    let mut data = Vec::with_capacity(4 + 4 + name.len());
    data.extend_from_slice(&TL_PREFIX_OVERLAY);
    // TL bytes encoding: length as 1-4 bytes + data
    if name.len() < 254 {
        data.push(name.len() as u8);
    } else {
        data.push(254);
        data.push((name.len() & 0xFF) as u8);
        data.push(((name.len() >> 8) & 0xFF) as u8);
        data.push(((name.len() >> 16) & 0xFF) as u8);
    }
    data.extend_from_slice(name);
    // Pad to 4-byte boundary
    let padding = (4 - (data.len() % 4)) % 4;
    data.extend(std::iter::repeat_n(0u8, padding));
    sha256(&data)
}

/// A wrapper type for a 32-byte key ID.
///
/// This provides type safety to distinguish key IDs from raw byte arrays.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct KeyId([u8; 32]);

impl KeyId {
    /// Create a new KeyId from raw bytes.
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Create a KeyId from an Ed25519 public key.
    pub fn from_ed25519_public_key(public_key: &[u8; 32]) -> Self {
        Self(calculate_key_id(public_key))
    }

    /// Get the raw bytes of the key ID.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Convert to a hex string for display/debugging.
    pub fn to_hex(&self) -> String {
        self.0.iter().map(|b| format!("{:02x}", b)).collect()
    }

    /// Create from a hex string.
    ///
    /// # Errors
    /// Returns None if the string is not valid hex or wrong length.
    pub fn from_hex(hex: &str) -> Option<Self> {
        if hex.len() != 64 {
            return None;
        }

        let mut bytes = [0u8; 32];
        for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
            let s = std::str::from_utf8(chunk).ok()?;
            bytes[i] = u8::from_str_radix(s, 16).ok()?;
        }
        Some(Self(bytes))
    }
}

impl From<[u8; 32]> for KeyId {
    fn from(bytes: [u8; 32]) -> Self {
        Self::new(bytes)
    }
}

impl AsRef<[u8; 32]> for KeyId {
    fn as_ref(&self) -> &[u8; 32] {
        &self.0
    }
}

impl AsRef<[u8]> for KeyId {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ed25519::Ed25519Keypair;

    #[test]
    fn test_calculate_key_id() {
        // Test with a known public key
        let public_key = [0u8; 32];
        let key_id = calculate_key_id(&public_key);

        // The key ID should be SHA256 of prefix + public key
        let mut expected_input = Vec::new();
        expected_input.extend_from_slice(&TL_PREFIX_ED25519);
        expected_input.extend_from_slice(&public_key);
        let expected = sha256(&expected_input);

        assert_eq!(key_id, expected);
    }

    #[test]
    fn test_different_keys_different_ids() {
        let keypair1 = Ed25519Keypair::generate();
        let keypair2 = Ed25519Keypair::generate();

        let id1 = calculate_key_id(&keypair1.public_key);
        let id2 = calculate_key_id(&keypair2.public_key);

        assert_ne!(id1, id2);
    }

    #[test]
    fn test_same_key_same_id() {
        let keypair = Ed25519Keypair::generate();

        let id1 = calculate_key_id(&keypair.public_key);
        let id2 = calculate_key_id(&keypair.public_key);

        assert_eq!(id1, id2);
    }

    #[test]
    fn test_key_id_type() {
        let keypair = Ed25519Keypair::generate();
        let key_id = KeyId::from_ed25519_public_key(&keypair.public_key);

        assert_eq!(key_id.as_bytes().len(), 32);
    }

    #[test]
    fn test_key_id_hex_conversion() {
        let bytes = [0x42u8; 32];
        let key_id = KeyId::new(bytes);

        let hex = key_id.to_hex();
        assert_eq!(hex.len(), 64);

        let restored = KeyId::from_hex(&hex).unwrap();
        assert_eq!(key_id, restored);
    }

    #[test]
    fn test_key_id_from_hex_invalid() {
        // Too short
        assert!(KeyId::from_hex("abcd").is_none());

        // Invalid characters
        assert!(KeyId::from_hex(&"zz".repeat(32)).is_none());
    }

    #[test]
    fn test_tl_prefix_values() {
        // Verify the TL prefix constants are correct
        // pub.ed25519 schema CRC32 in little-endian
        assert_eq!(TL_PREFIX_ED25519, [0xC6, 0xB4, 0x13, 0x48]);
    }

    #[test]
    fn test_aes_key_id() {
        let key = [0x42u8; 32];
        let key_id = calculate_aes_key_id(&key);

        // Should use AES prefix
        let mut expected_input = Vec::new();
        expected_input.extend_from_slice(&TL_PREFIX_AES);
        expected_input.extend_from_slice(&key);
        let expected = sha256(&expected_input);

        assert_eq!(key_id, expected);
    }
}
