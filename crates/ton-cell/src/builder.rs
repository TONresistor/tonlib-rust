//! CellBuilder for constructing TON cells.
//!
//! The builder allows storing bits, integers, bytes, and references
//! to other cells, then building the final Cell.

use std::sync::Arc;

use crate::{Cell, CellError, CellResult, CellSlice, CellType, MsgAddress, MAX_CELL_BITS, MAX_CELL_REFS};

/// Builder for constructing TON cells.
///
/// CellBuilder provides methods to store various data types into a cell,
/// then finalize it with `build()`.
///
/// # Example
///
/// ```
/// use ton_cell::CellBuilder;
///
/// let mut builder = CellBuilder::new();
/// builder.store_u32(0x12345678).unwrap();
/// builder.store_bytes(&[1, 2, 3, 4]).unwrap();
/// let cell = builder.build().unwrap();
/// ```
#[derive(Debug, Clone)]
pub struct CellBuilder {
    /// Data buffer.
    data: Vec<u8>,
    /// Current bit position within the buffer.
    bit_len: usize,
    /// References to other cells.
    references: Vec<Arc<Cell>>,
    /// Cell type (defaults to Ordinary).
    cell_type: CellType,
}

impl CellBuilder {
    /// Create a new empty CellBuilder.
    pub fn new() -> Self {
        CellBuilder {
            data: Vec::with_capacity(128),
            bit_len: 0,
            references: Vec::new(),
            cell_type: CellType::Ordinary,
        }
    }

    /// Create a builder with a specific cell type.
    pub fn with_type(cell_type: CellType) -> Self {
        CellBuilder {
            data: Vec::with_capacity(128),
            bit_len: 0,
            references: Vec::new(),
            cell_type,
        }
    }

    /// Store a single bit.
    pub fn store_bit(&mut self, bit: bool) -> CellResult<&mut Self> {
        if self.bit_len >= MAX_CELL_BITS {
            return Err(CellError::DataTooLong(self.bit_len + 1));
        }

        let byte_index = self.bit_len / 8;
        let bit_index = 7 - (self.bit_len % 8);

        // Extend data buffer if needed
        if byte_index >= self.data.len() {
            self.data.push(0);
        }

        if bit {
            self.data[byte_index] |= 1 << bit_index;
        }

        self.bit_len += 1;
        Ok(self)
    }

    /// Store multiple bits.
    pub fn store_bits(&mut self, bits: &[bool]) -> CellResult<&mut Self> {
        for &bit in bits {
            self.store_bit(bit)?;
        }
        Ok(self)
    }

    /// Store an unsigned 8-bit integer.
    pub fn store_u8(&mut self, value: u8) -> CellResult<&mut Self> {
        self.store_uint(value as u64, 8)
    }

    /// Store an unsigned 16-bit integer (big-endian).
    pub fn store_u16(&mut self, value: u16) -> CellResult<&mut Self> {
        self.store_uint(value as u64, 16)
    }

    /// Store an unsigned 32-bit integer (big-endian).
    pub fn store_u32(&mut self, value: u32) -> CellResult<&mut Self> {
        self.store_uint(value as u64, 32)
    }

    /// Store an unsigned 64-bit integer (big-endian).
    pub fn store_u64(&mut self, value: u64) -> CellResult<&mut Self> {
        self.store_uint(value, 64)
    }

    /// Store a signed 8-bit integer.
    pub fn store_i8(&mut self, value: i8) -> CellResult<&mut Self> {
        self.store_int(value as i64, 8)
    }

    /// Store a signed 16-bit integer (big-endian).
    pub fn store_i16(&mut self, value: i16) -> CellResult<&mut Self> {
        self.store_int(value as i64, 16)
    }

    /// Store a signed 32-bit integer (big-endian).
    pub fn store_i32(&mut self, value: i32) -> CellResult<&mut Self> {
        self.store_int(value as i64, 32)
    }

    /// Store a signed 64-bit integer (big-endian).
    pub fn store_i64(&mut self, value: i64) -> CellResult<&mut Self> {
        self.store_int(value, 64)
    }

    /// Store an unsigned integer with a specific bit width.
    ///
    /// The value is stored in big-endian format.
    pub fn store_uint(&mut self, value: u64, bits: usize) -> CellResult<&mut Self> {
        if bits == 0 {
            return Ok(self);
        }

        if bits > 64 {
            return Err(CellError::InvalidBitLength(bits));
        }

        if self.bit_len + bits > MAX_CELL_BITS {
            return Err(CellError::DataTooLong(self.bit_len + bits));
        }

        // Store bits from most significant to least significant
        for i in (0..bits).rev() {
            let bit = ((value >> i) & 1) == 1;
            self.store_bit(bit)?;
        }

        Ok(self)
    }

    /// Store a signed integer with a specific bit width.
    ///
    /// The value is stored in two's complement, big-endian format.
    pub fn store_int(&mut self, value: i64, bits: usize) -> CellResult<&mut Self> {
        if bits == 0 {
            return Ok(self);
        }

        if bits > 64 {
            return Err(CellError::InvalidBitLength(bits));
        }

        // Convert to unsigned for bit manipulation
        // For negative numbers, this gives us the two's complement representation
        let unsigned = value as u64;

        self.store_uint(unsigned, bits)
    }

    /// Store a byte array.
    pub fn store_bytes(&mut self, bytes: &[u8]) -> CellResult<&mut Self> {
        for &byte in bytes {
            self.store_u8(byte)?;
        }
        Ok(self)
    }

    /// Store the contents of a CellSlice.
    pub fn store_slice(&mut self, slice: &CellSlice) -> CellResult<&mut Self> {
        // Store remaining bits
        let bits_left = slice.bits_left();
        for i in 0..bits_left {
            let bit = slice.get_bit_at(slice.bit_offset + i);
            self.store_bit(bit)?;
        }

        // Store remaining references
        for i in slice.ref_offset..slice.cell.reference_count() {
            if let Some(reference) = slice.cell.reference(i) {
                self.store_ref(reference.clone())?;
            }
        }

        Ok(self)
    }

    /// Store a reference to another cell.
    pub fn store_ref(&mut self, cell: Arc<Cell>) -> CellResult<&mut Self> {
        if self.references.len() >= MAX_CELL_REFS {
            return Err(CellError::TooManyRefs(self.references.len() + 1));
        }

        self.references.push(cell);
        Ok(self)
    }

    /// Store coins (VarUInteger 16).
    ///
    /// This is the standard format for storing nanoton amounts in TON.
    /// Format: 4 bits for byte length, then the value in that many bytes.
    pub fn store_coins(&mut self, nanotons: u128) -> CellResult<&mut Self> {
        if nanotons == 0 {
            // Zero is stored as 4 zero bits (length = 0)
            return self.store_uint(0, 4);
        }

        // Calculate how many bytes we need
        let bytes_needed = (128 - nanotons.leading_zeros()).div_ceil(8);
        let bytes_needed = bytes_needed.max(1) as usize;

        if bytes_needed > 15 {
            return Err(CellError::DataTooLong(bytes_needed * 8 + 4));
        }

        // Store length (4 bits)
        self.store_uint(bytes_needed as u64, 4)?;

        // Store value bytes (big-endian)
        for i in (0..bytes_needed).rev() {
            let byte = ((nanotons >> (i * 8)) & 0xFF) as u8;
            self.store_u8(byte)?;
        }

        Ok(self)
    }

    /// Store a message address.
    pub fn store_address(&mut self, addr: &MsgAddress) -> CellResult<&mut Self> {
        match addr {
            MsgAddress::Null => {
                // addr_none$00
                self.store_uint(0b00, 2)
            }
            MsgAddress::External { len, data } => {
                // addr_extern$01 len:(## 9) external_address:(bits len)
                self.store_uint(0b01, 2)?;
                self.store_uint(*len as u64, 9)?;
                for i in 0..(*len as usize) {
                    let byte_idx = i / 8;
                    let bit_idx = 7 - (i % 8);
                    let bit = if byte_idx < data.len() {
                        (data[byte_idx] >> bit_idx) & 1 == 1
                    } else {
                        false
                    };
                    self.store_bit(bit)?;
                }
                Ok(self)
            }
            MsgAddress::Internal { workchain, address } => {
                // We use addr_std$10 format (not addr_var$11)
                // addr_std$10 anycast:(Maybe Anycast) workchain_id:int8 address:bits256
                self.store_uint(0b10, 2)?;
                // No anycast (0 bit)
                self.store_bit(false)?;
                // Workchain ID (8 bits, signed)
                self.store_int(*workchain as i64, 8)?;
                // Address (256 bits)
                self.store_bytes(address)
            }
        }
    }

    /// Get the number of bits that can still be stored.
    pub fn bits_left(&self) -> usize {
        MAX_CELL_BITS - self.bit_len
    }

    /// Get the number of references that can still be added.
    pub fn refs_left(&self) -> usize {
        MAX_CELL_REFS - self.references.len()
    }

    /// Get the current number of bits stored.
    pub fn bit_len(&self) -> usize {
        self.bit_len
    }

    /// Get the current number of references.
    pub fn ref_count(&self) -> usize {
        self.references.len()
    }

    /// Build the cell.
    ///
    /// This consumes the builder and returns the constructed Cell.
    pub fn build(self) -> CellResult<Cell> {
        Ok(Cell::new(
            self.data,
            self.bit_len,
            self.references,
            self.cell_type,
        ))
    }
}

impl Default for CellBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_builder() {
        let builder = CellBuilder::new();
        assert_eq!(builder.bit_len(), 0);
        assert_eq!(builder.ref_count(), 0);
        assert_eq!(builder.bits_left(), MAX_CELL_BITS);
        assert_eq!(builder.refs_left(), MAX_CELL_REFS);
    }

    #[test]
    fn test_store_bit() {
        let mut builder = CellBuilder::new();
        builder.store_bit(true).unwrap();
        builder.store_bit(false).unwrap();
        builder.store_bit(true).unwrap();

        assert_eq!(builder.bit_len(), 3);

        let cell = builder.build().unwrap();
        assert_eq!(cell.data(), &[0b10100000]);
    }

    #[test]
    fn test_store_uint() {
        let mut builder = CellBuilder::new();
        builder.store_uint(0b10101, 5).unwrap();

        assert_eq!(builder.bit_len(), 5);

        let cell = builder.build().unwrap();
        // 10101 stored from bit 0: 10101000
        assert_eq!(cell.data(), &[0b10101000]);
    }

    #[test]
    fn test_store_u32() {
        let mut builder = CellBuilder::new();
        builder.store_u32(0x12345678).unwrap();

        let cell = builder.build().unwrap();
        assert_eq!(cell.data(), &[0x12, 0x34, 0x56, 0x78]);
    }
}
