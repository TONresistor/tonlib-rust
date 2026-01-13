//! TON TL (Type Language) Serialization Library
//!
//! This crate provides TL serialization and deserialization for the TON network.
//!
//! TL (Type Language) is a binary serialization format used throughout TON for:
//! - ADNL protocol messages
//! - DHT queries and responses
//! - Overlay network messages
//! - Lite Client API
//!
//! # Overview
//!
//! TL uses a schema-driven approach where each type has a unique 32-bit constructor ID
//! (the CRC32 of the type's schema definition). Messages are serialized as:
//!
//! ```text
//! [constructor_id: 4 bytes][field1][field2]...[fieldN]
//! ```
//!
//! # Basic Types
//!
//! - `int` / `int32`: 4-byte signed integer (little-endian)
//! - `long` / `int64`: 8-byte signed integer (little-endian)
//! - `int128`: 16-byte integer
//! - `int256`: 32-byte integer
//! - `bytes`: Length-prefixed byte array with padding
//! - `string`: Length-prefixed UTF-8 string with padding
//!
//! # Example
//!
//! ```rust
//! use ton_tl::{TlWriter, TlReader, TlSerialize, TlDeserialize, PublicKey};
//!
//! // Create a writer and serialize some data
//! let mut writer = TlWriter::new();
//! writer.write_i32(42);
//! writer.write_string("Hello, TON!");
//!
//! // Read the data back
//! let mut reader = TlReader::new(writer.as_bytes());
//! let value = reader.read_i32().unwrap();
//! let message = reader.read_string().unwrap();
//!
//! assert_eq!(value, 42);
//! assert_eq!(message, "Hello, TON!");
//! ```

use thiserror::Error;

mod reader;
mod writer;
mod types;

pub use reader::TlReader;
pub use writer::TlWriter;
pub use types::*;

// ============================================================================
// Error Types
// ============================================================================

/// Errors that can occur during TL serialization/deserialization.
#[derive(Debug, Error, Clone, PartialEq)]
pub enum TlError {
    /// Not enough bytes to read the expected type.
    #[error("Unexpected end of data: need {needed} bytes, have {available}")]
    UnexpectedEof { needed: usize, available: usize },

    /// The constructor ID doesn't match any known type.
    #[error("Unknown constructor ID: 0x{0:08x}")]
    UnknownConstructor(u32),

    /// The data is malformed.
    #[error("Invalid TL data: {0}")]
    InvalidData(String),

    /// String is not valid UTF-8.
    #[error("Invalid UTF-8 string")]
    InvalidUtf8,

    /// Invalid boolean constructor ID.
    #[error("Invalid boolean constructor ID: 0x{0:08x}")]
    InvalidBool(u32),
}

/// Result type for TL operations.
pub type TlResult<T> = Result<T, TlError>;

// ============================================================================
// Common TL Schema IDs
// ============================================================================

/// boolTrue = Bool
pub const TL_BOOL_TRUE: u32 = 0x997275b5;

/// boolFalse = Bool
pub const TL_BOOL_FALSE: u32 = 0xbc799737;

/// null = Null
pub const TL_NULL: u32 = 0x56730bcc;

/// vector {t:Type} # [t] = Vector t
pub const TL_VECTOR: u32 = 0x1cb5c415;

/// pub.ed25519 key:int256 = PublicKey
pub const TL_PUB_ED25519: u32 = 0x4813b4c6;

/// pub.aes key:int256 = PublicKey
pub const TL_PUB_AES: u32 = 0x2dbcadd4;

/// pub.overlay name:bytes = PublicKey
pub const TL_PUB_OVERLAY: u32 = 0x34ba45cb;

/// pk.ed25519 key:int256 = PrivateKey
pub const TL_PK_ED25519: u32 = 0x3f479ccc;

/// pk.aes key:int256 = PrivateKey
pub const TL_PK_AES: u32 = 0xe9b1e54a;

// ============================================================================
// Serialization Traits
// ============================================================================

/// Trait for types that can be serialized to TL format.
pub trait TlSerialize {
    /// Get the TL constructor ID for this type.
    ///
    /// Panics for union types that don't have a single ID.
    fn tl_id() -> u32
    where
        Self: Sized;

    /// Serialize this value to a TL writer (without constructor ID).
    fn serialize(&self, writer: &mut TlWriter);

    /// Serialize this value to a TL writer with constructor ID prefix.
    fn serialize_boxed(&self, writer: &mut TlWriter)
    where
        Self: Sized,
    {
        writer.write_id(Self::tl_id());
        self.serialize(writer);
    }

    /// Serialize to a new byte vector with constructor ID.
    fn to_bytes(&self) -> Vec<u8>
    where
        Self: Sized,
    {
        let mut writer = TlWriter::new();
        self.serialize_boxed(&mut writer);
        writer.into_bytes()
    }

    /// Serialize to a new byte vector without constructor ID.
    fn to_bytes_bare(&self) -> Vec<u8> {
        let mut writer = TlWriter::new();
        self.serialize(&mut writer);
        writer.into_bytes()
    }
}

/// Trait for types that can be deserialized from TL format.
pub trait TlDeserialize: Sized {
    /// Deserialize this value from a TL reader (without reading constructor ID).
    fn deserialize(reader: &mut TlReader) -> TlResult<Self>;

    /// Deserialize from a byte slice.
    fn from_bytes(data: &[u8]) -> TlResult<Self> {
        let mut reader = TlReader::new(data);
        Self::deserialize(&mut reader)
    }
}

// ============================================================================
// Legacy Traits (for backwards compatibility)
// ============================================================================

/// Legacy trait for types that can be serialized to TL format.
pub trait TlWrite {
    /// Write this value to a TL buffer.
    fn write_to(&self, buffer: &mut Vec<u8>);

    /// Serialize to a new byte vector.
    fn to_tl_bytes(&self) -> Vec<u8> {
        let mut buffer = Vec::new();
        self.write_to(&mut buffer);
        buffer
    }
}

/// Legacy trait for types that can be deserialized from TL format.
pub trait TlRead: Sized {
    /// Read this value from a TL buffer.
    ///
    /// Returns the parsed value and the number of bytes consumed.
    fn read_from(data: &[u8]) -> TlResult<(Self, usize)>;

    /// Deserialize from a byte slice.
    fn from_tl_bytes(data: &[u8]) -> TlResult<Self> {
        let (value, _) = Self::read_from(data)?;
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_writer_reader_i32() {
        let mut writer = TlWriter::new();
        writer.write_i32(42);
        writer.write_i32(-100);
        writer.write_i32(i32::MAX);
        writer.write_i32(i32::MIN);

        let mut reader = TlReader::new(writer.as_bytes());
        assert_eq!(reader.read_i32().unwrap(), 42);
        assert_eq!(reader.read_i32().unwrap(), -100);
        assert_eq!(reader.read_i32().unwrap(), i32::MAX);
        assert_eq!(reader.read_i32().unwrap(), i32::MIN);
        assert!(reader.is_empty());
    }

    #[test]
    fn test_writer_reader_u32() {
        let mut writer = TlWriter::new();
        writer.write_u32(0);
        writer.write_u32(42);
        writer.write_u32(u32::MAX);

        let mut reader = TlReader::new(writer.as_bytes());
        assert_eq!(reader.read_u32().unwrap(), 0);
        assert_eq!(reader.read_u32().unwrap(), 42);
        assert_eq!(reader.read_u32().unwrap(), u32::MAX);
        assert!(reader.is_empty());
    }

    #[test]
    fn test_writer_reader_i64() {
        let mut writer = TlWriter::new();
        writer.write_i64(42);
        writer.write_i64(-100);
        writer.write_i64(i64::MAX);
        writer.write_i64(i64::MIN);

        let mut reader = TlReader::new(writer.as_bytes());
        assert_eq!(reader.read_i64().unwrap(), 42);
        assert_eq!(reader.read_i64().unwrap(), -100);
        assert_eq!(reader.read_i64().unwrap(), i64::MAX);
        assert_eq!(reader.read_i64().unwrap(), i64::MIN);
        assert!(reader.is_empty());
    }

    #[test]
    fn test_writer_reader_u64() {
        let mut writer = TlWriter::new();
        writer.write_u64(0);
        writer.write_u64(42);
        writer.write_u64(u64::MAX);

        let mut reader = TlReader::new(writer.as_bytes());
        assert_eq!(reader.read_u64().unwrap(), 0);
        assert_eq!(reader.read_u64().unwrap(), 42);
        assert_eq!(reader.read_u64().unwrap(), u64::MAX);
        assert!(reader.is_empty());
    }

    #[test]
    fn test_writer_reader_i128() {
        let mut writer = TlWriter::new();
        writer.write_i128(42);
        writer.write_i128(-100);
        writer.write_i128(i128::MAX);
        writer.write_i128(i128::MIN);

        let mut reader = TlReader::new(writer.as_bytes());
        assert_eq!(reader.read_i128().unwrap(), 42);
        assert_eq!(reader.read_i128().unwrap(), -100);
        assert_eq!(reader.read_i128().unwrap(), i128::MAX);
        assert_eq!(reader.read_i128().unwrap(), i128::MIN);
        assert!(reader.is_empty());
    }

    #[test]
    fn test_writer_reader_u128() {
        let mut writer = TlWriter::new();
        writer.write_u128(0);
        writer.write_u128(42);
        writer.write_u128(u128::MAX);

        let mut reader = TlReader::new(writer.as_bytes());
        assert_eq!(reader.read_u128().unwrap(), 0);
        assert_eq!(reader.read_u128().unwrap(), 42);
        assert_eq!(reader.read_u128().unwrap(), u128::MAX);
        assert!(reader.is_empty());
    }

    #[test]
    fn test_writer_reader_i256() {
        let value: [u8; 32] = [
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
            25, 26, 27, 28, 29, 30, 31, 32,
        ];
        let mut writer = TlWriter::new();
        writer.write_i256(&value);

        let mut reader = TlReader::new(writer.as_bytes());
        assert_eq!(reader.read_i256().unwrap(), value);
        assert!(reader.is_empty());
    }

    #[test]
    fn test_writer_reader_u256() {
        let value: [u8; 32] = [0xff; 32];
        let mut writer = TlWriter::new();
        writer.write_u256(&value);

        let mut reader = TlReader::new(writer.as_bytes());
        assert_eq!(reader.read_u256().unwrap(), value);
        assert!(reader.is_empty());
    }

    #[test]
    fn test_writer_reader_bool() {
        let mut writer = TlWriter::new();
        writer.write_bool(true);
        writer.write_bool(false);

        let mut reader = TlReader::new(writer.as_bytes());
        assert!(reader.read_bool().unwrap());
        assert!(!reader.read_bool().unwrap());
        assert!(reader.is_empty());
    }

    #[test]
    fn test_bytes_short() {
        // Test bytes < 254 bytes
        let data = b"Hello, World!";
        let mut writer = TlWriter::new();
        writer.write_bytes(data);

        let bytes = writer.as_bytes();
        // Length byte + data + padding to 4-byte boundary
        // 1 + 13 = 14, padding = (4 - 14 % 4) % 4 = 2, total = 16
        assert_eq!(bytes.len(), 16);
        assert_eq!(bytes[0], 13); // Length

        let mut reader = TlReader::new(bytes);
        let read_data = reader.read_bytes().unwrap();
        assert_eq!(read_data, data);
        assert!(reader.is_empty());
    }

    #[test]
    fn test_bytes_long() {
        // Test bytes >= 254 bytes
        let data: Vec<u8> = (0..300).map(|i| (i % 256) as u8).collect();
        let mut writer = TlWriter::new();
        writer.write_bytes(&data);

        let bytes = writer.as_bytes();
        assert_eq!(bytes[0], 0xFE); // Long format marker

        let mut reader = TlReader::new(bytes);
        let read_data = reader.read_bytes().unwrap();
        assert_eq!(read_data, data);
        assert!(reader.is_empty());
    }

    #[test]
    fn test_bytes_empty() {
        let data: &[u8] = &[];
        let mut writer = TlWriter::new();
        writer.write_bytes(data);

        let bytes = writer.as_bytes();
        // Length byte (0) + 3 padding bytes = 4
        assert_eq!(bytes.len(), 4);
        assert_eq!(bytes[0], 0);

        let mut reader = TlReader::new(bytes);
        let read_data = reader.read_bytes().unwrap();
        assert_eq!(read_data, data);
        assert!(reader.is_empty());
    }

    #[test]
    fn test_bytes_exactly_253() {
        let data: Vec<u8> = (0..253).map(|i| (i % 256) as u8).collect();
        let mut writer = TlWriter::new();
        writer.write_bytes(&data);

        let bytes = writer.as_bytes();
        // Short format: 1 byte length + 253 bytes data = 254, padding = 2
        assert_eq!(bytes[0], 253);
        assert_eq!(bytes.len(), 256);

        let mut reader = TlReader::new(bytes);
        let read_data = reader.read_bytes().unwrap();
        assert_eq!(read_data, data);
        assert!(reader.is_empty());
    }

    #[test]
    fn test_bytes_exactly_254() {
        let data: Vec<u8> = (0..254).map(|i| (i % 256) as u8).collect();
        let mut writer = TlWriter::new();
        writer.write_bytes(&data);

        let bytes = writer.as_bytes();
        // Long format: 0xFE + 3 bytes length + 254 bytes data = 258, padding = 2
        assert_eq!(bytes[0], 0xFE);
        assert_eq!(bytes.len(), 260);

        let mut reader = TlReader::new(bytes);
        let read_data = reader.read_bytes().unwrap();
        assert_eq!(read_data, data);
        assert!(reader.is_empty());
    }

    #[test]
    fn test_string() {
        let s = "Hello, TON!";
        let mut writer = TlWriter::new();
        writer.write_string(s);

        let mut reader = TlReader::new(writer.as_bytes());
        let read_s = reader.read_string().unwrap();
        assert_eq!(read_s, s);
        assert!(reader.is_empty());
    }

    #[test]
    fn test_string_utf8() {
        let s = "Hello, \u{1F4A1}!"; // With emoji
        let mut writer = TlWriter::new();
        writer.write_string(s);

        let mut reader = TlReader::new(writer.as_bytes());
        let read_s = reader.read_string().unwrap();
        assert_eq!(read_s, s);
        assert!(reader.is_empty());
    }

    #[test]
    fn test_raw() {
        let data = b"raw data";
        let mut writer = TlWriter::new();
        writer.write_raw(data);

        let bytes = writer.as_bytes();
        assert_eq!(bytes, data);

        let mut reader = TlReader::new(bytes);
        let read_data = reader.read_raw(data.len()).unwrap();
        assert_eq!(read_data, data);
        assert!(reader.is_empty());
    }

    #[test]
    fn test_id() {
        let mut writer = TlWriter::new();
        writer.write_id(TL_BOOL_TRUE);
        writer.write_id(TL_PUB_ED25519);

        let mut reader = TlReader::new(writer.as_bytes());
        assert_eq!(reader.read_id().unwrap(), TL_BOOL_TRUE);
        assert_eq!(reader.read_id().unwrap(), TL_PUB_ED25519);
        assert!(reader.is_empty());
    }

    #[test]
    fn test_peek_id() {
        let mut writer = TlWriter::new();
        writer.write_id(TL_BOOL_TRUE);

        let reader = TlReader::new(writer.as_bytes());
        // Peek should not advance the position
        assert_eq!(reader.peek_id().unwrap(), TL_BOOL_TRUE);
        assert_eq!(reader.peek_id().unwrap(), TL_BOOL_TRUE);
        assert!(!reader.is_empty());
    }

    #[test]
    fn test_vector() {
        let items: Vec<i32> = vec![1, 2, 3, 4, 5];
        let mut writer = TlWriter::new();
        writer.write_vector(&items, |w, item| w.write_i32(*item));

        let mut reader = TlReader::new(writer.as_bytes());
        let read_items: Vec<i32> = reader
            .read_vector(|r| r.read_i32())
            .unwrap();
        assert_eq!(read_items, items);
        assert!(reader.is_empty());
    }

    #[test]
    fn test_vector_empty() {
        let items: Vec<i32> = vec![];
        let mut writer = TlWriter::new();
        writer.write_vector(&items, |w, item| w.write_i32(*item));

        let mut reader = TlReader::new(writer.as_bytes());
        let read_items: Vec<i32> = reader
            .read_vector(|r| r.read_i32())
            .unwrap();
        assert_eq!(read_items, items);
        assert!(reader.is_empty());
    }

    #[test]
    fn test_public_key_ed25519() {
        let key = [42u8; 32];
        let pk = PublicKey::Ed25519 { key };

        let mut writer = TlWriter::new();
        pk.serialize(&mut writer);

        let mut reader = TlReader::new(writer.as_bytes());
        let read_pk = PublicKey::deserialize(&mut reader).unwrap();
        assert_eq!(read_pk, pk);
        assert!(reader.is_empty());
    }

    #[test]
    fn test_public_key_aes() {
        let key = [0xAB; 32];
        let pk = PublicKey::Aes { key };

        let mut writer = TlWriter::new();
        pk.serialize(&mut writer);

        let mut reader = TlReader::new(writer.as_bytes());
        let read_pk = PublicKey::deserialize(&mut reader).unwrap();
        assert_eq!(read_pk, pk);
        assert!(reader.is_empty());
    }

    #[test]
    fn test_public_key_overlay() {
        let name = b"test overlay".to_vec();
        let pk = PublicKey::Overlay { name: name.clone() };

        let mut writer = TlWriter::new();
        pk.serialize(&mut writer);

        let mut reader = TlReader::new(writer.as_bytes());
        let read_pk = PublicKey::deserialize(&mut reader).unwrap();
        assert_eq!(read_pk, pk);
        assert!(reader.is_empty());
    }

    #[test]
    fn test_private_key_ed25519() {
        let key = [42u8; 32];
        let pk = PrivateKey::Ed25519 { key };

        let mut writer = TlWriter::new();
        pk.serialize(&mut writer);

        let mut reader = TlReader::new(writer.as_bytes());
        let read_pk = PrivateKey::deserialize(&mut reader).unwrap();
        assert_eq!(read_pk, pk);
        assert!(reader.is_empty());
    }

    #[test]
    fn test_private_key_aes() {
        let key = [0xCD; 32];
        let pk = PrivateKey::Aes { key };

        let mut writer = TlWriter::new();
        pk.serialize(&mut writer);

        let mut reader = TlReader::new(writer.as_bytes());
        let read_pk = PrivateKey::deserialize(&mut reader).unwrap();
        assert_eq!(read_pk, pk);
        assert!(reader.is_empty());
    }

    #[test]
    fn test_remaining_and_skip() {
        let mut writer = TlWriter::new();
        writer.write_i32(1);
        writer.write_i32(2);
        writer.write_i32(3);

        let mut reader = TlReader::new(writer.as_bytes());
        assert_eq!(reader.remaining(), 12);

        reader.skip(4).unwrap();
        assert_eq!(reader.remaining(), 8);

        reader.skip(4).unwrap();
        assert_eq!(reader.remaining(), 4);

        assert_eq!(reader.read_i32().unwrap(), 3);
        assert!(reader.is_empty());
    }

    #[test]
    fn test_error_eof() {
        let data = [0u8; 2];
        let mut reader = TlReader::new(&data);
        let result = reader.read_i32();
        assert!(matches!(result, Err(TlError::UnexpectedEof { .. })));
    }

    #[test]
    fn test_error_invalid_bool() {
        let mut writer = TlWriter::new();
        writer.write_u32(0x12345678); // Invalid bool ID

        let mut reader = TlReader::new(writer.as_bytes());
        let result = reader.read_bool();
        assert!(matches!(result, Err(TlError::InvalidBool(_))));
    }

    #[test]
    fn test_complex_roundtrip() {
        // Test a complex structure with multiple types
        let mut writer = TlWriter::new();

        // Write various types
        writer.write_id(TL_PUB_ED25519);
        writer.write_i32(42);
        writer.write_u64(0xDEADBEEF);
        writer.write_bool(true);
        writer.write_string("test string");
        writer.write_bytes(b"test bytes");

        let key = [0xAB; 32];
        writer.write_u256(&key);

        let items: Vec<u32> = vec![100, 200, 300];
        writer.write_vector(&items, |w, item| w.write_u32(*item));

        // Read back
        let mut reader = TlReader::new(writer.as_bytes());

        assert_eq!(reader.read_id().unwrap(), TL_PUB_ED25519);
        assert_eq!(reader.read_i32().unwrap(), 42);
        assert_eq!(reader.read_u64().unwrap(), 0xDEADBEEF);
        assert!(reader.read_bool().unwrap());
        assert_eq!(reader.read_string().unwrap(), "test string");
        assert_eq!(reader.read_bytes().unwrap(), b"test bytes");
        assert_eq!(reader.read_u256().unwrap(), key);

        let read_items: Vec<u32> = reader
            .read_vector(|r| r.read_u32())
            .unwrap();
        assert_eq!(read_items, items);

        assert!(reader.is_empty());
    }

    #[test]
    fn test_with_capacity() {
        let writer = TlWriter::with_capacity(1024);
        assert!(writer.as_bytes().is_empty());
    }

    #[test]
    fn test_schema_ids() {
        // Verify schema IDs match expected values
        assert_eq!(TL_BOOL_TRUE, 0x997275b5);
        assert_eq!(TL_BOOL_FALSE, 0xbc799737);
        assert_eq!(TL_NULL, 0x56730bcc);
        assert_eq!(TL_VECTOR, 0x1cb5c415);
        assert_eq!(TL_PUB_ED25519, 0x4813b4c6);
        assert_eq!(TL_PUB_AES, 0x2dbcadd4);
        assert_eq!(TL_PUB_OVERLAY, 0x34ba45cb);
        assert_eq!(TL_PK_ED25519, 0x3f479ccc);
        assert_eq!(TL_PK_AES, 0xe9b1e54a);
    }
}
