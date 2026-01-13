//! TL type definitions
//!
//! This module contains common TL types used in TON protocols.

use crate::{
    TlDeserialize, TlError, TlReader, TlResult, TlSerialize, TlWriter,
    TL_PK_AES, TL_PK_ED25519, TL_PUB_AES, TL_PUB_ED25519, TL_PUB_OVERLAY,
};

// ============================================================================
// PublicKey
// ============================================================================

/// TL PublicKey type union.
///
/// Represents various public key types used in TON:
/// - `pub.ed25519` - Ed25519 public key (32 bytes)
/// - `pub.aes` - AES key (32 bytes)
/// - `pub.overlay` - Overlay network identifier (variable length)
///
/// # TL Schema
///
/// ```text
/// pub.ed25519 key:int256 = PublicKey;
/// pub.aes key:int256 = PublicKey;
/// pub.overlay name:bytes = PublicKey;
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum PublicKey {
    /// Ed25519 public key.
    Ed25519 {
        /// The 32-byte public key.
        key: [u8; 32],
    },
    /// AES key (used for symmetric encryption).
    Aes {
        /// The 32-byte AES key.
        key: [u8; 32],
    },
    /// Overlay network identifier.
    Overlay {
        /// The overlay name/identifier.
        name: Vec<u8>,
    },
}

impl PublicKey {
    /// Create a new Ed25519 public key.
    #[inline]
    pub fn ed25519(key: [u8; 32]) -> Self {
        Self::Ed25519 { key }
    }

    /// Create a new AES public key.
    #[inline]
    pub fn aes(key: [u8; 32]) -> Self {
        Self::Aes { key }
    }

    /// Create a new overlay public key.
    #[inline]
    pub fn overlay(name: Vec<u8>) -> Self {
        Self::Overlay { name }
    }

    /// Get the key bytes if this is an Ed25519 or AES key.
    pub fn key_bytes(&self) -> Option<&[u8; 32]> {
        match self {
            Self::Ed25519 { key } | Self::Aes { key } => Some(key),
            Self::Overlay { .. } => None,
        }
    }

    /// Check if this is an Ed25519 key.
    #[inline]
    pub fn is_ed25519(&self) -> bool {
        matches!(self, Self::Ed25519 { .. })
    }

    /// Check if this is an AES key.
    #[inline]
    pub fn is_aes(&self) -> bool {
        matches!(self, Self::Aes { .. })
    }

    /// Check if this is an overlay key.
    #[inline]
    pub fn is_overlay(&self) -> bool {
        matches!(self, Self::Overlay { .. })
    }

    /// Get the TL constructor ID for this variant.
    pub fn variant_id(&self) -> u32 {
        match self {
            Self::Ed25519 { .. } => TL_PUB_ED25519,
            Self::Aes { .. } => TL_PUB_AES,
            Self::Overlay { .. } => TL_PUB_OVERLAY,
        }
    }
}

impl TlSerialize for PublicKey {
    fn tl_id() -> u32 {
        panic!("PublicKey is a union type - use variant_id() instead")
    }

    fn serialize(&self, writer: &mut TlWriter) {
        match self {
            PublicKey::Ed25519 { key } => {
                writer.write_id(TL_PUB_ED25519);
                writer.write_u256(key);
            }
            PublicKey::Aes { key } => {
                writer.write_id(TL_PUB_AES);
                writer.write_u256(key);
            }
            PublicKey::Overlay { name } => {
                writer.write_id(TL_PUB_OVERLAY);
                writer.write_bytes(name);
            }
        }
    }

    fn serialize_boxed(&self, writer: &mut TlWriter) {
        // For union types, serialize already includes the variant ID
        self.serialize(writer);
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut writer = TlWriter::new();
        self.serialize(&mut writer);
        writer.into_bytes()
    }
}

impl TlDeserialize for PublicKey {
    fn deserialize(reader: &mut TlReader) -> TlResult<Self> {
        let id = reader.read_id()?;
        match id {
            TL_PUB_ED25519 => {
                let key = reader.read_u256()?;
                Ok(PublicKey::Ed25519 { key })
            }
            TL_PUB_AES => {
                let key = reader.read_u256()?;
                Ok(PublicKey::Aes { key })
            }
            TL_PUB_OVERLAY => {
                let name = reader.read_bytes()?;
                Ok(PublicKey::Overlay { name })
            }
            _ => Err(TlError::UnknownConstructor(id)),
        }
    }
}

// ============================================================================
// PrivateKey
// ============================================================================

/// TL PrivateKey type union.
///
/// Represents various private key types used in TON:
/// - `pk.ed25519` - Ed25519 private key (32 bytes)
/// - `pk.aes` - AES key (32 bytes)
///
/// # TL Schema
///
/// ```text
/// pk.ed25519 key:int256 = PrivateKey;
/// pk.aes key:int256 = PrivateKey;
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PrivateKey {
    /// Ed25519 private key.
    Ed25519 {
        /// The 32-byte private key (seed).
        key: [u8; 32],
    },
    /// AES key (used for symmetric encryption).
    Aes {
        /// The 32-byte AES key.
        key: [u8; 32],
    },
}

impl PrivateKey {
    /// Create a new Ed25519 private key.
    #[inline]
    pub fn ed25519(key: [u8; 32]) -> Self {
        Self::Ed25519 { key }
    }

    /// Create a new AES private key.
    #[inline]
    pub fn aes(key: [u8; 32]) -> Self {
        Self::Aes { key }
    }

    /// Get the key bytes.
    pub fn key_bytes(&self) -> &[u8; 32] {
        match self {
            Self::Ed25519 { key } | Self::Aes { key } => key,
        }
    }

    /// Check if this is an Ed25519 key.
    #[inline]
    pub fn is_ed25519(&self) -> bool {
        matches!(self, Self::Ed25519 { .. })
    }

    /// Check if this is an AES key.
    #[inline]
    pub fn is_aes(&self) -> bool {
        matches!(self, Self::Aes { .. })
    }

    /// Get the TL constructor ID for this variant.
    pub fn variant_id(&self) -> u32 {
        match self {
            Self::Ed25519 { .. } => TL_PK_ED25519,
            Self::Aes { .. } => TL_PK_AES,
        }
    }
}

impl TlSerialize for PrivateKey {
    fn tl_id() -> u32 {
        panic!("PrivateKey is a union type - use variant_id() instead")
    }

    fn serialize(&self, writer: &mut TlWriter) {
        match self {
            PrivateKey::Ed25519 { key } => {
                writer.write_id(TL_PK_ED25519);
                writer.write_u256(key);
            }
            PrivateKey::Aes { key } => {
                writer.write_id(TL_PK_AES);
                writer.write_u256(key);
            }
        }
    }

    fn serialize_boxed(&self, writer: &mut TlWriter) {
        // For union types, serialize already includes the variant ID
        self.serialize(writer);
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut writer = TlWriter::new();
        self.serialize(&mut writer);
        writer.into_bytes()
    }
}

impl TlDeserialize for PrivateKey {
    fn deserialize(reader: &mut TlReader) -> TlResult<Self> {
        let id = reader.read_id()?;
        match id {
            TL_PK_ED25519 => {
                let key = reader.read_u256()?;
                Ok(PrivateKey::Ed25519 { key })
            }
            TL_PK_AES => {
                let key = reader.read_u256()?;
                Ok(PrivateKey::Aes { key })
            }
            _ => Err(TlError::UnknownConstructor(id)),
        }
    }
}

// ============================================================================
// TL Null
// ============================================================================

/// TL Null type.
///
/// Represents a null/empty value in TL.
///
/// # TL Schema
///
/// ```text
/// null = Null;
/// ```
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct TlNull;

impl TlSerialize for TlNull {
    fn tl_id() -> u32 {
        crate::TL_NULL
    }

    fn serialize(&self, _writer: &mut TlWriter) {
        // Null has no fields
    }
}

impl TlDeserialize for TlNull {
    fn deserialize(_reader: &mut TlReader) -> TlResult<Self> {
        // Null has no fields to read
        Ok(TlNull)
    }
}

// ============================================================================
// Helper Implementations
// ============================================================================

/// Helper function to compute TL-style CRC32 for schema normalization.
///
/// Note: This is a simplified implementation. Full schema ID computation
/// requires proper schema normalization first.
pub fn compute_schema_id(schema: &str) -> u32 {
    crc32_ieee(schema.as_bytes())
}

/// Compute IEEE CRC32 of data.
fn crc32_ieee(data: &[u8]) -> u32 {
    const CRC32_TABLE: [u32; 256] = generate_crc32_table();

    let mut crc = 0xFFFFFFFFu32;
    for byte in data {
        let index = ((crc ^ (*byte as u32)) & 0xFF) as usize;
        crc = (crc >> 8) ^ CRC32_TABLE[index];
    }
    !crc
}

/// Generate CRC32 lookup table at compile time.
const fn generate_crc32_table() -> [u32; 256] {
    let mut table = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        let mut crc = i as u32;
        let mut j = 0;
        while j < 8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ 0xEDB88320;
            } else {
                crc >>= 1;
            }
            j += 1;
        }
        table[i] = crc;
        i += 1;
    }
    table
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_public_key_ed25519_roundtrip() {
        let key = [0x42u8; 32];
        let pk = PublicKey::ed25519(key);

        let bytes = pk.to_bytes();
        let parsed = PublicKey::from_bytes(&bytes).unwrap();

        assert_eq!(pk, parsed);
        assert!(parsed.is_ed25519());
        assert_eq!(parsed.key_bytes(), Some(&key));
    }

    #[test]
    fn test_public_key_aes_roundtrip() {
        let key = [0xAB; 32];
        let pk = PublicKey::aes(key);

        let bytes = pk.to_bytes();
        let parsed = PublicKey::from_bytes(&bytes).unwrap();

        assert_eq!(pk, parsed);
        assert!(parsed.is_aes());
    }

    #[test]
    fn test_public_key_overlay_roundtrip() {
        let name = b"test-overlay-name".to_vec();
        let pk = PublicKey::overlay(name.clone());

        let bytes = pk.to_bytes();
        let parsed = PublicKey::from_bytes(&bytes).unwrap();

        assert_eq!(pk, parsed);
        assert!(parsed.is_overlay());
    }

    #[test]
    fn test_private_key_ed25519_roundtrip() {
        let key = [0x12; 32];
        let pk = PrivateKey::ed25519(key);

        let bytes = pk.to_bytes();
        let parsed = PrivateKey::from_bytes(&bytes).unwrap();

        assert_eq!(pk, parsed);
        assert!(parsed.is_ed25519());
        assert_eq!(parsed.key_bytes(), &key);
    }

    #[test]
    fn test_private_key_aes_roundtrip() {
        let key = [0xCD; 32];
        let pk = PrivateKey::aes(key);

        let bytes = pk.to_bytes();
        let parsed = PrivateKey::from_bytes(&bytes).unwrap();

        assert_eq!(pk, parsed);
        assert!(parsed.is_aes());
    }

    #[test]
    fn test_null_roundtrip() {
        let null = TlNull;

        let mut writer = TlWriter::new();
        null.serialize_boxed(&mut writer);

        let mut reader = TlReader::new(writer.as_bytes());
        let id = reader.read_id().unwrap();
        assert_eq!(id, crate::TL_NULL);

        let parsed = TlNull::deserialize(&mut reader).unwrap();
        assert_eq!(null, parsed);
    }

    #[test]
    fn test_public_key_variant_id() {
        let ed25519 = PublicKey::ed25519([0; 32]);
        let aes = PublicKey::aes([0; 32]);
        let overlay = PublicKey::overlay(vec![]);

        assert_eq!(ed25519.variant_id(), TL_PUB_ED25519);
        assert_eq!(aes.variant_id(), TL_PUB_AES);
        assert_eq!(overlay.variant_id(), TL_PUB_OVERLAY);
    }

    #[test]
    fn test_private_key_variant_id() {
        let ed25519 = PrivateKey::ed25519([0; 32]);
        let aes = PrivateKey::aes([0; 32]);

        assert_eq!(ed25519.variant_id(), TL_PK_ED25519);
        assert_eq!(aes.variant_id(), TL_PK_AES);
    }

    #[test]
    fn test_unknown_constructor() {
        let mut writer = TlWriter::new();
        writer.write_id(0xDEADBEEF);
        writer.write_u256(&[0; 32]);

        let result = PublicKey::from_bytes(writer.as_bytes());
        assert!(matches!(result, Err(TlError::UnknownConstructor(0xDEADBEEF))));
    }

    #[test]
    fn test_crc32() {
        // Test some known CRC32 values
        assert_eq!(crc32_ieee(b""), 0x00000000);
        assert_eq!(crc32_ieee(b"123456789"), 0xCBF43926);
    }
}
