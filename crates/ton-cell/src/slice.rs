//! CellSlice for reading data from TON cells.
//!
//! A CellSlice provides methods to sequentially read data from a cell,
//! tracking the current position within the cell's data and references.

use crate::{Cell, CellError, CellResult, MsgAddress};

/// A slice view into a Cell for reading data.
///
/// CellSlice tracks the current read position and allows sequential
/// reading of bits, integers, bytes, and references.
///
/// # Example
///
/// ```
/// use ton_cell::{CellBuilder, CellSlice};
///
/// let mut builder = CellBuilder::new();
/// builder.store_u32(0x12345678).unwrap();
/// let cell = builder.build().unwrap();
///
/// let mut slice = CellSlice::new(&cell);
/// let value = slice.load_u32().unwrap();
/// assert_eq!(value, 0x12345678);
/// ```
#[derive(Debug, Clone)]
pub struct CellSlice<'a> {
    /// Reference to the underlying cell.
    pub(crate) cell: &'a Cell,
    /// Current bit offset within the cell data.
    pub(crate) bit_offset: usize,
    /// Number of bits remaining (from bit_offset).
    pub(crate) bit_len: usize,
    /// Current reference offset.
    pub(crate) ref_offset: usize,
}

impl<'a> CellSlice<'a> {
    /// Create a new slice from a cell.
    pub fn new(cell: &'a Cell) -> Self {
        CellSlice {
            cell,
            bit_offset: 0,
            bit_len: cell.bit_len(),
            ref_offset: 0,
        }
    }

    /// Load a single bit.
    pub fn load_bit(&mut self) -> CellResult<bool> {
        if self.bit_len == 0 {
            return Err(CellError::NotEnoughBits { need: 1, have: 0 });
        }

        let bit = self.get_bit_at(self.bit_offset);
        self.bit_offset += 1;
        self.bit_len -= 1;
        Ok(bit)
    }

    /// Load multiple bits.
    pub fn load_bits(&mut self, count: usize) -> CellResult<Vec<bool>> {
        if count > self.bit_len {
            return Err(CellError::NotEnoughBits {
                need: count,
                have: self.bit_len,
            });
        }

        let mut result = Vec::with_capacity(count);
        for _ in 0..count {
            result.push(self.load_bit()?);
        }
        Ok(result)
    }

    /// Load an unsigned 8-bit integer.
    pub fn load_u8(&mut self) -> CellResult<u8> {
        self.load_uint(8).map(|v| v as u8)
    }

    /// Load an unsigned 16-bit integer (big-endian).
    pub fn load_u16(&mut self) -> CellResult<u16> {
        self.load_uint(16).map(|v| v as u16)
    }

    /// Load an unsigned 32-bit integer (big-endian).
    pub fn load_u32(&mut self) -> CellResult<u32> {
        self.load_uint(32).map(|v| v as u32)
    }

    /// Load an unsigned 64-bit integer (big-endian).
    pub fn load_u64(&mut self) -> CellResult<u64> {
        self.load_uint(64)
    }

    /// Load a signed 8-bit integer.
    pub fn load_i8(&mut self) -> CellResult<i8> {
        self.load_int(8).map(|v| v as i8)
    }

    /// Load a signed 16-bit integer (big-endian).
    pub fn load_i16(&mut self) -> CellResult<i16> {
        self.load_int(16).map(|v| v as i16)
    }

    /// Load a signed 32-bit integer (big-endian).
    pub fn load_i32(&mut self) -> CellResult<i32> {
        self.load_int(32).map(|v| v as i32)
    }

    /// Load a signed 64-bit integer (big-endian).
    pub fn load_i64(&mut self) -> CellResult<i64> {
        self.load_int(64)
    }

    /// Load an unsigned integer with a specific bit width.
    pub fn load_uint(&mut self, bits: usize) -> CellResult<u64> {
        if bits == 0 {
            return Ok(0);
        }

        if bits > 64 {
            return Err(CellError::InvalidBitLength(bits));
        }

        if bits > self.bit_len {
            return Err(CellError::NotEnoughBits {
                need: bits,
                have: self.bit_len,
            });
        }

        let mut result: u64 = 0;
        for _ in 0..bits {
            result = (result << 1) | (self.load_bit()? as u64);
        }

        Ok(result)
    }

    /// Load a signed integer with a specific bit width (two's complement).
    pub fn load_int(&mut self, bits: usize) -> CellResult<i64> {
        if bits == 0 {
            return Ok(0);
        }

        if bits > 64 {
            return Err(CellError::InvalidBitLength(bits));
        }

        let unsigned = self.load_uint(bits)?;

        // Sign extend if needed
        if bits < 64 {
            let sign_bit = 1u64 << (bits - 1);
            if (unsigned & sign_bit) != 0 {
                // Negative number, sign extend
                let mask = !((1u64 << bits) - 1);
                Ok((unsigned | mask) as i64)
            } else {
                Ok(unsigned as i64)
            }
        } else {
            Ok(unsigned as i64)
        }
    }

    /// Load a byte array.
    pub fn load_bytes(&mut self, count: usize) -> CellResult<Vec<u8>> {
        let bits_needed = count * 8;
        if bits_needed > self.bit_len {
            return Err(CellError::NotEnoughBits {
                need: bits_needed,
                have: self.bit_len,
            });
        }

        let mut result = Vec::with_capacity(count);
        for _ in 0..count {
            result.push(self.load_u8()?);
        }
        Ok(result)
    }

    /// Load a reference to another cell.
    pub fn load_ref(&mut self) -> CellResult<&'a Cell> {
        let refs_left = self.cell.reference_count() - self.ref_offset;
        if refs_left == 0 {
            return Err(CellError::NotEnoughRefs { need: 1, have: 0 });
        }

        let reference = self
            .cell
            .reference(self.ref_offset)
            .ok_or(CellError::CellNotFound(self.ref_offset))?;
        self.ref_offset += 1;
        Ok(reference.as_ref())
    }

    /// Load coins (VarUInteger 16).
    ///
    /// Format: 4 bits for byte length, then the value in that many bytes.
    pub fn load_coins(&mut self) -> CellResult<u128> {
        let byte_len = self.load_uint(4)? as usize;

        if byte_len == 0 {
            return Ok(0);
        }

        let mut result: u128 = 0;
        for _ in 0..byte_len {
            result = (result << 8) | (self.load_u8()? as u128);
        }

        Ok(result)
    }

    /// Load a message address.
    pub fn load_address(&mut self) -> CellResult<MsgAddress> {
        let addr_type = self.load_uint(2)? as u8;

        match addr_type {
            0b00 => {
                // addr_none$00
                Ok(MsgAddress::Null)
            }
            0b01 => {
                // addr_extern$01 len:(## 9) external_address:(bits len)
                let len = self.load_uint(9)? as u16;
                let byte_len = (len as usize).div_ceil(8);
                let mut data = vec![0u8; byte_len];

                for i in 0..(len as usize) {
                    let byte_idx = i / 8;
                    let bit_idx = 7 - (i % 8);
                    if self.load_bit()? {
                        data[byte_idx] |= 1 << bit_idx;
                    }
                }

                Ok(MsgAddress::External { len, data })
            }
            0b10 => {
                // addr_std$10 anycast:(Maybe Anycast) workchain_id:int8 address:bits256
                let anycast = self.load_bit()?;
                if anycast {
                    // Skip anycast info: depth:5 rewrite_pfx:(depth * Bit)
                    let depth = self.load_uint(5)?;
                    self.skip_bits(depth as usize)?;
                }

                let workchain = self.load_int(8)? as i32;
                let address_bytes = self.load_bytes(32)?;
                let mut address = [0u8; 32];
                address.copy_from_slice(&address_bytes);

                Ok(MsgAddress::Internal { workchain, address })
            }
            0b11 => {
                // addr_var$11 anycast:(Maybe Anycast) addr_len:(## 9) workchain_id:int32 address:(bits addr_len)
                let anycast = self.load_bit()?;
                if anycast {
                    let depth = self.load_uint(5)?;
                    self.skip_bits(depth as usize)?;
                }

                let addr_len = self.load_uint(9)? as usize;
                let workchain = self.load_int(32)? as i32;

                // Load address bits into bytes
                let mut address = [0u8; 32];

                for i in 0..addr_len.min(256) {
                    let byte_idx = i / 8;
                    let bit_idx = 7 - (i % 8);
                    if byte_idx < 32 && self.load_bit()? {
                        address[byte_idx] |= 1 << bit_idx;
                    }
                }

                // Skip any remaining bits if addr_len > 256
                if addr_len > 256 {
                    self.skip_bits(addr_len - 256)?;
                }

                Ok(MsgAddress::Internal { workchain, address })
            }
            _ => Err(CellError::InvalidAddress(format!(
                "Unknown address type: {}",
                addr_type
            ))),
        }
    }

    /// Get the number of bits remaining.
    pub fn bits_left(&self) -> usize {
        self.bit_len
    }

    /// Get the number of references remaining.
    pub fn refs_left(&self) -> usize {
        self.cell.reference_count() - self.ref_offset
    }

    /// Skip a number of bits.
    pub fn skip_bits(&mut self, count: usize) -> CellResult<()> {
        if count > self.bit_len {
            return Err(CellError::NotEnoughBits {
                need: count,
                have: self.bit_len,
            });
        }

        self.bit_offset += count;
        self.bit_len -= count;
        Ok(())
    }

    /// Skip a number of references.
    pub fn skip_refs(&mut self, count: usize) -> CellResult<()> {
        let refs_left = self.refs_left();
        if count > refs_left {
            return Err(CellError::NotEnoughRefs {
                need: count,
                have: refs_left,
            });
        }

        self.ref_offset += count;
        Ok(())
    }

    /// Check if the slice is empty (no bits or refs left).
    pub fn is_empty(&self) -> bool {
        self.bit_len == 0 && self.refs_left() == 0
    }

    /// Get the bit value at a specific position.
    pub(crate) fn get_bit_at(&self, index: usize) -> bool {
        let byte_index = index / 8;
        let bit_index = 7 - (index % 8);

        if byte_index < self.cell.data().len() {
            (self.cell.data()[byte_index] >> bit_index) & 1 == 1
        } else {
            false
        }
    }

    /// Get the underlying cell.
    pub fn cell(&self) -> &'a Cell {
        self.cell
    }

    /// Get the current bit offset.
    pub fn bit_offset(&self) -> usize {
        self.bit_offset
    }

    /// Get the current reference offset.
    pub fn ref_offset(&self) -> usize {
        self.ref_offset
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CellBuilder;

    #[test]
    fn test_load_bit() {
        let mut builder = CellBuilder::new();
        builder.store_bit(true).unwrap();
        builder.store_bit(false).unwrap();
        builder.store_bit(true).unwrap();
        let cell = builder.build().unwrap();

        let mut slice = CellSlice::new(&cell);
        assert!(slice.load_bit().unwrap());
        assert!(!slice.load_bit().unwrap());
        assert!(slice.load_bit().unwrap());
        assert!(slice.load_bit().is_err()); // No more bits
    }

    #[test]
    fn test_load_uint() {
        let mut builder = CellBuilder::new();
        builder.store_uint(0b10101, 5).unwrap();
        let cell = builder.build().unwrap();

        let mut slice = CellSlice::new(&cell);
        assert_eq!(slice.load_uint(5).unwrap(), 0b10101);
    }

    #[test]
    fn test_load_int_negative() {
        let mut builder = CellBuilder::new();
        builder.store_int(-15, 8).unwrap();
        let cell = builder.build().unwrap();

        let mut slice = CellSlice::new(&cell);
        assert_eq!(slice.load_int(8).unwrap(), -15);
    }
}
