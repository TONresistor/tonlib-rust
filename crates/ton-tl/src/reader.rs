//! TL Reader implementation
//!
//! Provides deserialization of TL primitive types from bytes.

use crate::{TlError, TlResult, TL_BOOL_FALSE, TL_BOOL_TRUE, TL_VECTOR};

/// TL Reader for deserializing data from TL format.
///
/// All data is read in little-endian byte order as per TL specification.
#[derive(Debug, Clone)]
pub struct TlReader<'a> {
    data: &'a [u8],
    offset: usize,
}

impl<'a> TlReader<'a> {
    /// Create a new TL reader from a byte slice.
    #[inline]
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, offset: 0 }
    }

    // ========================================================================
    // Primitive Types
    // ========================================================================

    /// Read a signed 32-bit integer (TL `int`).
    #[inline]
    pub fn read_i32(&mut self) -> TlResult<i32> {
        let bytes = self.read_exact::<4>()?;
        Ok(i32::from_le_bytes(bytes))
    }

    /// Read an unsigned 32-bit integer.
    #[inline]
    pub fn read_u32(&mut self) -> TlResult<u32> {
        let bytes = self.read_exact::<4>()?;
        Ok(u32::from_le_bytes(bytes))
    }

    /// Read a signed 64-bit integer (TL `long`).
    #[inline]
    pub fn read_i64(&mut self) -> TlResult<i64> {
        let bytes = self.read_exact::<8>()?;
        Ok(i64::from_le_bytes(bytes))
    }

    /// Read an unsigned 64-bit integer.
    #[inline]
    pub fn read_u64(&mut self) -> TlResult<u64> {
        let bytes = self.read_exact::<8>()?;
        Ok(u64::from_le_bytes(bytes))
    }

    /// Read a signed 128-bit integer (TL `int128`).
    #[inline]
    pub fn read_i128(&mut self) -> TlResult<i128> {
        let bytes = self.read_exact::<16>()?;
        Ok(i128::from_le_bytes(bytes))
    }

    /// Read an unsigned 128-bit integer.
    #[inline]
    pub fn read_u128(&mut self) -> TlResult<u128> {
        let bytes = self.read_exact::<16>()?;
        Ok(u128::from_le_bytes(bytes))
    }

    /// Read a signed 256-bit integer (TL `int256`).
    ///
    /// Returns the value as a 32-byte array in little-endian order.
    #[inline]
    pub fn read_i256(&mut self) -> TlResult<[u8; 32]> {
        self.read_exact::<32>()
    }

    /// Read an unsigned 256-bit integer.
    ///
    /// Returns the value as a 32-byte array in little-endian order.
    #[inline]
    pub fn read_u256(&mut self) -> TlResult<[u8; 32]> {
        self.read_exact::<32>()
    }

    /// Read a boolean value (TL `Bool`).
    ///
    /// Booleans are deserialized from their constructor IDs:
    /// - `boolTrue` (0x997275b5) -> `true`
    /// - `boolFalse` (0xbc799737) -> `false`
    #[inline]
    pub fn read_bool(&mut self) -> TlResult<bool> {
        let id = self.read_u32()?;
        match id {
            TL_BOOL_TRUE => Ok(true),
            TL_BOOL_FALSE => Ok(false),
            _ => Err(TlError::InvalidBool(id)),
        }
    }

    // ========================================================================
    // Bytes and Strings
    // ========================================================================

    /// Read a byte array with TL length prefix and padding (TL `bytes`).
    ///
    /// # TL Bytes Decoding
    ///
    /// - If first byte < 254: length is that byte, data follows, then padding
    /// - If first byte == 254: length is next 3 bytes (LE), data follows, then padding
    /// - If first byte == 255: length is next 8 bytes (LE), data follows, then padding
    pub fn read_bytes(&mut self) -> TlResult<Vec<u8>> {
        // Read first byte
        let first_byte = self.read_byte()?;

        let (len, header_size) = if first_byte < 254 {
            // Short format: length is the first byte
            (first_byte as usize, 1)
        } else if first_byte == 254 {
            // Medium format: 0xFE + 3 bytes length (little-endian)
            let len_bytes = self.read_exact::<3>()?;
            let len = u32::from_le_bytes([len_bytes[0], len_bytes[1], len_bytes[2], 0]) as usize;
            (len, 4)
        } else {
            // Long format: 0xFF + 8 bytes length (little-endian)
            let len_bytes = self.read_exact::<8>()?;
            let len = u64::from_le_bytes(len_bytes) as usize;
            (len, 9)
        };

        // Read the actual data
        let data = self.read_raw(len)?.to_vec();

        // Calculate and skip padding
        // Total bytes: header_size (1, 4, or 9) + data length
        let total = header_size + len;
        let padding = (4 - (total % 4)) % 4;
        self.skip(padding)?;

        Ok(data)
    }

    /// Read a string with TL length prefix and padding (TL `string`).
    ///
    /// The bytes are interpreted as UTF-8.
    pub fn read_string(&mut self) -> TlResult<String> {
        let bytes = self.read_bytes()?;
        String::from_utf8(bytes).map_err(|_| TlError::InvalidUtf8)
    }

    /// Read raw bytes without length prefix or padding.
    ///
    /// Returns a slice into the original data.
    #[inline]
    pub fn read_raw(&mut self, len: usize) -> TlResult<&'a [u8]> {
        self.check_remaining(len)?;
        let data = &self.data[self.offset..self.offset + len];
        self.offset += len;
        Ok(data)
    }

    // ========================================================================
    // Schema ID
    // ========================================================================

    /// Read a TL constructor ID (schema ID).
    #[inline]
    pub fn read_id(&mut self) -> TlResult<u32> {
        self.read_u32()
    }

    /// Peek at the next constructor ID without advancing the reader.
    #[inline]
    pub fn peek_id(&self) -> TlResult<u32> {
        self.check_remaining(4)?;
        let bytes = [
            self.data[self.offset],
            self.data[self.offset + 1],
            self.data[self.offset + 2],
            self.data[self.offset + 3],
        ];
        Ok(u32::from_le_bytes(bytes))
    }

    // ========================================================================
    // Vectors
    // ========================================================================

    /// Read a vector of items (TL `vector`).
    ///
    /// Expects the vector constructor ID (0x1cb5c415) followed by a 32-bit count,
    /// then each item in sequence.
    ///
    /// # Arguments
    ///
    /// * `read_item` - A function to deserialize each item
    ///
    /// # Example
    ///
    /// ```rust
    /// use ton_tl::TlReader;
    ///
    /// let data = [0x15, 0xc4, 0xb5, 0x1c, 0x02, 0x00, 0x00, 0x00,
    ///             0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00];
    /// let mut reader = TlReader::new(&data);
    /// let numbers: Vec<i32> = reader.read_vector(|r| r.read_i32()).unwrap();
    /// assert_eq!(numbers, vec![1, 2]);
    /// ```
    pub fn read_vector<T, F>(&mut self, read_item: F) -> TlResult<Vec<T>>
    where
        F: Fn(&mut Self) -> TlResult<T>,
    {
        // Read and verify vector constructor ID
        let id = self.read_id()?;
        if id != TL_VECTOR {
            return Err(TlError::UnknownConstructor(id));
        }

        // Read count
        let count = self.read_u32()? as usize;

        // Read items
        let mut items = Vec::with_capacity(count);
        for _ in 0..count {
            items.push(read_item(self)?);
        }

        Ok(items)
    }

    /// Read a vector of items without expecting a constructor ID.
    ///
    /// Use this when deserializing bare vectors where the constructor ID
    /// is not expected.
    pub fn read_vector_bare<T, F>(&mut self, read_item: F) -> TlResult<Vec<T>>
    where
        F: Fn(&mut Self) -> TlResult<T>,
    {
        // Read count only (no constructor ID)
        let count = self.read_u32()? as usize;

        // Read items
        let mut items = Vec::with_capacity(count);
        for _ in 0..count {
            items.push(read_item(self)?);
        }

        Ok(items)
    }

    // ========================================================================
    // Position and Navigation
    // ========================================================================

    /// Get the number of bytes remaining to read.
    #[inline]
    pub fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.offset)
    }

    /// Check if there are no more bytes to read.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.offset >= self.data.len()
    }

    /// Skip a number of bytes.
    #[inline]
    pub fn skip(&mut self, count: usize) -> TlResult<()> {
        self.check_remaining(count)?;
        self.offset += count;
        Ok(())
    }

    /// Get the current offset position.
    #[inline]
    pub fn position(&self) -> usize {
        self.offset
    }

    /// Set the current offset position.
    ///
    /// # Panics
    ///
    /// Panics if position is greater than the data length.
    #[inline]
    pub fn set_position(&mut self, position: usize) {
        assert!(position <= self.data.len());
        self.offset = position;
    }

    /// Get a reference to the remaining data.
    #[inline]
    pub fn remaining_data(&self) -> &'a [u8] {
        &self.data[self.offset..]
    }

    // ========================================================================
    // Internal Helpers
    // ========================================================================

    /// Check if there are enough bytes remaining.
    #[inline]
    fn check_remaining(&self, needed: usize) -> TlResult<()> {
        let available = self.remaining();
        if available < needed {
            Err(TlError::UnexpectedEof { needed, available })
        } else {
            Ok(())
        }
    }

    /// Read exactly N bytes into an array.
    #[inline]
    fn read_exact<const N: usize>(&mut self) -> TlResult<[u8; N]> {
        self.check_remaining(N)?;
        let mut bytes = [0u8; N];
        bytes.copy_from_slice(&self.data[self.offset..self.offset + N]);
        self.offset += N;
        Ok(bytes)
    }

    /// Read a single byte.
    #[inline]
    fn read_byte(&mut self) -> TlResult<u8> {
        self.check_remaining(1)?;
        let byte = self.data[self.offset];
        self.offset += 1;
        Ok(byte)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_read_i32() {
        let data = [0x78, 0x56, 0x34, 0x12];
        let mut reader = TlReader::new(&data);
        assert_eq!(reader.read_i32().unwrap(), 0x12345678);
        assert!(reader.is_empty());
    }

    #[test]
    fn test_read_i32_negative() {
        let data = [0xFF, 0xFF, 0xFF, 0xFF];
        let mut reader = TlReader::new(&data);
        assert_eq!(reader.read_i32().unwrap(), -1);
    }

    #[test]
    fn test_read_u64() {
        let data = [0xF0, 0xDE, 0xBC, 0x9A, 0x78, 0x56, 0x34, 0x12];
        let mut reader = TlReader::new(&data);
        assert_eq!(reader.read_u64().unwrap(), 0x123456789ABCDEF0);
    }

    #[test]
    fn test_read_bytes_short() {
        // Length: 3, Data: "abc", aligned (no padding needed)
        let data = [3, b'a', b'b', b'c'];
        let mut reader = TlReader::new(&data);
        assert_eq!(reader.read_bytes().unwrap(), b"abc");
        assert!(reader.is_empty());
    }

    #[test]
    fn test_read_bytes_with_padding() {
        // Length: 2, Data: "ab", Padding: 1
        let data = [2, b'a', b'b', 0];
        let mut reader = TlReader::new(&data);
        assert_eq!(reader.read_bytes().unwrap(), b"ab");
        assert!(reader.is_empty());
    }

    #[test]
    fn test_read_bytes_empty() {
        // Length: 0, Padding: 3
        let data = [0, 0, 0, 0];
        let mut reader = TlReader::new(&data);
        assert_eq!(reader.read_bytes().unwrap(), Vec::<u8>::new());
        assert!(reader.is_empty());
    }

    #[test]
    fn test_read_bool() {
        let mut writer = crate::TlWriter::new();
        writer.write_bool(true);
        writer.write_bool(false);

        let mut reader = TlReader::new(writer.as_bytes());
        assert!(reader.read_bool().unwrap());
        assert!(!reader.read_bool().unwrap());
    }

    #[test]
    fn test_peek_id() {
        let data = TL_BOOL_TRUE.to_le_bytes();
        let reader = TlReader::new(&data);

        // Peek multiple times
        assert_eq!(reader.peek_id().unwrap(), TL_BOOL_TRUE);
        assert_eq!(reader.peek_id().unwrap(), TL_BOOL_TRUE);
        assert_eq!(reader.remaining(), 4);
    }

    #[test]
    fn test_error_eof() {
        let data = [0u8; 2];
        let mut reader = TlReader::new(&data);
        let result = reader.read_i32();
        assert!(matches!(
            result,
            Err(TlError::UnexpectedEof {
                needed: 4,
                available: 2
            })
        ));
    }

    #[test]
    fn test_remaining_data() {
        let data = [1, 2, 3, 4, 5, 6, 7, 8];
        let mut reader = TlReader::new(&data);
        reader.skip(4).unwrap();
        assert_eq!(reader.remaining_data(), &[5, 6, 7, 8]);
    }

    #[test]
    fn test_position() {
        let data = [1, 2, 3, 4, 5, 6, 7, 8];
        let mut reader = TlReader::new(&data);

        assert_eq!(reader.position(), 0);
        reader.skip(4).unwrap();
        assert_eq!(reader.position(), 4);

        reader.set_position(2);
        assert_eq!(reader.position(), 2);
        assert_eq!(reader.remaining(), 6);
    }
}
