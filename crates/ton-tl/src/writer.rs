//! TL Writer implementation
//!
//! Provides serialization of TL primitive types to bytes.

use crate::{TL_BOOL_FALSE, TL_BOOL_TRUE, TL_VECTOR};

/// TL Writer for serializing data to TL format.
///
/// All data is written in little-endian byte order as per TL specification.
#[derive(Debug, Clone, Default)]
pub struct TlWriter {
    buffer: Vec<u8>,
}

impl TlWriter {
    /// Create a new TL writer with empty buffer.
    #[inline]
    pub fn new() -> Self {
        Self { buffer: Vec::new() }
    }

    /// Create a new TL writer with pre-allocated capacity.
    #[inline]
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            buffer: Vec::with_capacity(capacity),
        }
    }

    // ========================================================================
    // Primitive Types
    // ========================================================================

    /// Write a signed 32-bit integer (TL `int`).
    #[inline]
    pub fn write_i32(&mut self, value: i32) {
        self.buffer.extend_from_slice(&value.to_le_bytes());
    }

    /// Write an unsigned 32-bit integer.
    #[inline]
    pub fn write_u32(&mut self, value: u32) {
        self.buffer.extend_from_slice(&value.to_le_bytes());
    }

    /// Write a signed 64-bit integer (TL `long`).
    #[inline]
    pub fn write_i64(&mut self, value: i64) {
        self.buffer.extend_from_slice(&value.to_le_bytes());
    }

    /// Write an unsigned 64-bit integer.
    #[inline]
    pub fn write_u64(&mut self, value: u64) {
        self.buffer.extend_from_slice(&value.to_le_bytes());
    }

    /// Write a signed 128-bit integer (TL `int128`).
    #[inline]
    pub fn write_i128(&mut self, value: i128) {
        self.buffer.extend_from_slice(&value.to_le_bytes());
    }

    /// Write an unsigned 128-bit integer.
    #[inline]
    pub fn write_u128(&mut self, value: u128) {
        self.buffer.extend_from_slice(&value.to_le_bytes());
    }

    /// Write a signed 256-bit integer (TL `int256`).
    ///
    /// The value is provided as a 32-byte array in little-endian order.
    #[inline]
    pub fn write_i256(&mut self, value: &[u8; 32]) {
        self.buffer.extend_from_slice(value);
    }

    /// Write an unsigned 256-bit integer.
    ///
    /// The value is provided as a 32-byte array in little-endian order.
    #[inline]
    pub fn write_u256(&mut self, value: &[u8; 32]) {
        self.buffer.extend_from_slice(value);
    }

    /// Write a boolean value (TL `Bool`).
    ///
    /// Booleans are serialized as their constructor IDs:
    /// - `true` -> `boolTrue` (0x997275b5)
    /// - `false` -> `boolFalse` (0xbc799737)
    #[inline]
    pub fn write_bool(&mut self, value: bool) {
        if value {
            self.write_u32(TL_BOOL_TRUE);
        } else {
            self.write_u32(TL_BOOL_FALSE);
        }
    }

    // ========================================================================
    // Bytes and Strings
    // ========================================================================

    /// Write a byte array with TL length prefix and padding (TL `bytes`).
    ///
    /// # TL Bytes Encoding
    ///
    /// - If length < 254: 1 byte length, then data, then padding to 4-byte boundary
    /// - If length >= 254 and < 16777216: 0xFE byte, 3 bytes length (LE), then data, then padding
    /// - If length >= 16777216: 0xFF byte, 8 bytes length (LE), then data, then padding
    ///
    /// Padding ensures the total length is a multiple of 4.
    pub fn write_bytes(&mut self, data: &[u8]) {
        let len = data.len();

        if len < 254 {
            // Short format: 1 byte length
            self.buffer.push(len as u8);
            self.buffer.extend_from_slice(data);

            // Calculate padding to 4-byte boundary
            // Total bytes so far: 1 (length) + len (data)
            let total = 1 + len;
            let padding = (4 - (total % 4)) % 4;
            self.buffer.extend(std::iter::repeat_n(0, padding));
        } else if len < 0x1000000 {
            // Medium format: 0xFE + 3 bytes length (for lengths 254 to 16777215)
            self.buffer.push(0xFE);
            let len_bytes = (len as u32).to_le_bytes();
            self.buffer.extend_from_slice(&len_bytes[..3]);
            self.buffer.extend_from_slice(data);

            // Calculate padding to 4-byte boundary
            // Total bytes so far: 4 (header) + len (data)
            let total = 4 + len;
            let padding = (4 - (total % 4)) % 4;
            self.buffer.extend(std::iter::repeat_n(0, padding));
        } else {
            // Long format: 0xFF + 8 bytes length (for lengths >= 16777216)
            self.buffer.push(0xFF);
            self.buffer.extend_from_slice(&(len as u64).to_le_bytes());
            self.buffer.extend_from_slice(data);

            // Calculate padding to 4-byte boundary
            // Total bytes so far: 9 (header) + len (data)
            let total = 9 + len;
            let padding = (4 - (total % 4)) % 4;
            self.buffer.extend(std::iter::repeat_n(0, padding));
        }
    }

    /// Write a string with TL length prefix and padding (TL `string`).
    ///
    /// Strings are encoded as UTF-8 bytes using the same format as `write_bytes`.
    #[inline]
    pub fn write_string(&mut self, s: &str) {
        self.write_bytes(s.as_bytes());
    }

    /// Write raw bytes without length prefix or padding.
    ///
    /// Use this for fixed-size fields or when you need to write bytes directly.
    #[inline]
    pub fn write_raw(&mut self, data: &[u8]) {
        self.buffer.extend_from_slice(data);
    }

    // ========================================================================
    // Schema ID
    // ========================================================================

    /// Write a TL constructor ID (schema ID).
    ///
    /// Constructor IDs are 32-bit unsigned integers written in little-endian.
    #[inline]
    pub fn write_id(&mut self, id: u32) {
        self.write_u32(id);
    }

    // ========================================================================
    // Vectors
    // ========================================================================

    /// Write a vector of items (TL `vector`).
    ///
    /// TL vectors are prefixed with the vector constructor ID (0x1cb5c415)
    /// followed by a 32-bit count, then each item serialized in sequence.
    ///
    /// # Arguments
    ///
    /// * `items` - The items to serialize
    /// * `write_item` - A function to serialize each item
    ///
    /// # Example
    ///
    /// ```rust
    /// use ton_tl::TlWriter;
    ///
    /// let mut writer = TlWriter::new();
    /// let numbers = vec![1i32, 2, 3, 4, 5];
    /// writer.write_vector(&numbers, |w, n| w.write_i32(*n));
    /// ```
    pub fn write_vector<T, F>(&mut self, items: &[T], write_item: F)
    where
        F: Fn(&mut Self, &T),
    {
        // Write vector constructor ID
        self.write_id(TL_VECTOR);

        // Write count
        self.write_u32(items.len() as u32);

        // Write each item
        for item in items {
            write_item(self, item);
        }
    }

    /// Write a vector of items without the vector constructor ID.
    ///
    /// Use this when serializing bare vectors where the constructor ID
    /// is not expected.
    ///
    /// # Arguments
    ///
    /// * `items` - The items to serialize
    /// * `write_item` - A function to serialize each item
    pub fn write_vector_bare<T, F>(&mut self, items: &[T], write_item: F)
    where
        F: Fn(&mut Self, &T),
    {
        // Write count only (no constructor ID)
        self.write_u32(items.len() as u32);

        // Write each item
        for item in items {
            write_item(self, item);
        }
    }

    // ========================================================================
    // Buffer Access
    // ========================================================================

    /// Consume the writer and return the internal buffer.
    #[inline]
    pub fn into_bytes(self) -> Vec<u8> {
        self.buffer
    }

    /// Get a reference to the internal buffer.
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        &self.buffer
    }

    /// Get the current length of the buffer.
    #[inline]
    pub fn len(&self) -> usize {
        self.buffer.len()
    }

    /// Check if the buffer is empty.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }

    /// Clear the buffer for reuse.
    #[inline]
    pub fn clear(&mut self) {
        self.buffer.clear();
    }

    /// Reserve additional capacity in the buffer.
    #[inline]
    pub fn reserve(&mut self, additional: usize) {
        self.buffer.reserve(additional);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_write_i32() {
        let mut writer = TlWriter::new();
        writer.write_i32(0x12345678);
        assert_eq!(writer.as_bytes(), &[0x78, 0x56, 0x34, 0x12]);
    }

    #[test]
    fn test_write_i32_negative() {
        let mut writer = TlWriter::new();
        writer.write_i32(-1);
        assert_eq!(writer.as_bytes(), &[0xFF, 0xFF, 0xFF, 0xFF]);
    }

    #[test]
    fn test_write_u64() {
        let mut writer = TlWriter::new();
        writer.write_u64(0x123456789ABCDEF0);
        assert_eq!(
            writer.as_bytes(),
            &[0xF0, 0xDE, 0xBC, 0x9A, 0x78, 0x56, 0x34, 0x12]
        );
    }

    #[test]
    fn test_write_bytes_short() {
        let mut writer = TlWriter::new();
        writer.write_bytes(b"abc");

        // Length: 3, Data: "abc", Padding: 0 (1+3=4, already aligned)
        assert_eq!(writer.as_bytes(), &[3, b'a', b'b', b'c']);
    }

    #[test]
    fn test_write_bytes_with_padding() {
        let mut writer = TlWriter::new();
        writer.write_bytes(b"ab");

        // Length: 2, Data: "ab", Padding: 1 (1+2=3, need 1 byte)
        assert_eq!(writer.as_bytes(), &[2, b'a', b'b', 0]);
    }

    #[test]
    fn test_write_bytes_long() {
        let mut writer = TlWriter::new();
        let data: Vec<u8> = (0..256).map(|i| i as u8).collect();
        writer.write_bytes(&data);

        // Should use long format
        assert_eq!(writer.as_bytes()[0], 0xFE);

        // Length should be 256 in little-endian (in 3 bytes)
        assert_eq!(writer.as_bytes()[1], 0x00);
        assert_eq!(writer.as_bytes()[2], 0x01);
        assert_eq!(writer.as_bytes()[3], 0x00);

        // Data starts at offset 4
        assert_eq!(&writer.as_bytes()[4..260], data.as_slice());
    }

    #[test]
    fn test_write_bool() {
        let mut writer = TlWriter::new();
        writer.write_bool(true);
        assert_eq!(writer.as_bytes(), &TL_BOOL_TRUE.to_le_bytes());

        let mut writer = TlWriter::new();
        writer.write_bool(false);
        assert_eq!(writer.as_bytes(), &TL_BOOL_FALSE.to_le_bytes());
    }

    #[test]
    fn test_write_vector() {
        let mut writer = TlWriter::new();
        let items: Vec<i32> = vec![1, 2, 3];
        writer.write_vector(&items, |w, &n| w.write_i32(n));

        // Vector ID + count + 3 * i32
        assert_eq!(writer.len(), 4 + 4 + 12);

        // Check vector ID
        assert_eq!(&writer.as_bytes()[0..4], &TL_VECTOR.to_le_bytes());

        // Check count
        assert_eq!(&writer.as_bytes()[4..8], &3u32.to_le_bytes());
    }

    #[test]
    fn test_clear_and_reuse() {
        let mut writer = TlWriter::new();
        writer.write_i32(42);
        assert!(!writer.is_empty());

        writer.clear();
        assert!(writer.is_empty());

        writer.write_i32(100);
        assert_eq!(writer.len(), 4);
    }
}
