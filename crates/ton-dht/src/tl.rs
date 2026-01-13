//! TL (Type Language) schemas and utilities for DHT.
//!
//! This module provides TL schema IDs and serialization helpers for DHT messages.

use crate::error::{DhtError, Result};

// ============================================================================
// DHT TL Schema IDs
// ============================================================================

/// dht.key id:int256 name:bytes idx:int = dht.Key
pub const DHT_KEY: u32 = 0xb1f06f8e;

/// dht.keyDescription key:dht.key id:PublicKey update_rule:dht.UpdateRule signature:bytes
pub const DHT_KEY_DESCRIPTION: u32 = 0xbb31d3da;

/// dht.updateRule.signature = dht.UpdateRule
pub const DHT_UPDATE_RULE_SIGNATURE: u32 = 0x10b5b3cc;

/// dht.updateRule.anybody = dht.UpdateRule
pub const DHT_UPDATE_RULE_ANYBODY: u32 = 0xd7e6c0f7;

/// dht.updateRule.overlayNodes = dht.UpdateRule
pub const DHT_UPDATE_RULE_OVERLAY_NODES: u32 = 0x5c0a70c5;

/// dht.value key:dht.keyDescription value:bytes ttl:int signature:bytes
pub const DHT_VALUE: u32 = 0xf3e6e7c0;

/// dht.node id:PublicKey addr_list:adnl.addressList version:int signature:bytes
pub const DHT_NODE: u32 = 0x84533248;

/// dht.nodes nodes:(vector dht.node) = dht.Nodes
pub const DHT_NODES: u32 = 0xcc2b8c1f;

/// dht.valueNotFound nodes:dht.nodes = dht.ValueResult
pub const DHT_VALUE_NOT_FOUND: u32 = 0xa3912b21;

/// dht.valueFound value:dht.Value = dht.ValueResult
pub const DHT_VALUE_FOUND: u32 = 0x6e2a5a96;

/// dht.findValue key:int256 k:int = dht.ValueResult
pub const DHT_FIND_VALUE: u32 = 0xa8f51e79;

/// dht.findNode key:int256 k:int = dht.Nodes
pub const DHT_FIND_NODE: u32 = 0x47bf71fd;

/// dht.store value:dht.Value = dht.Stored
pub const DHT_STORE: u32 = 0x29c40d72;

/// dht.stored = dht.Stored
pub const DHT_STORED: u32 = 0xd8e4dd15;

/// dht.ping random_id:long = dht.Pong
pub const DHT_PING: u32 = 0x75b0fc25;

/// dht.pong random_id:long = dht.Pong
pub const DHT_PONG: u32 = 0x85f9e713;

// ============================================================================
// ADNL TL Schema IDs (used by DHT)
// ============================================================================

/// adnl.addressList addrs:(vector adnl.Address) version:int reinit_date:int priority:int expire_at:int
pub const ADNL_ADDRESS_LIST: u32 = 0xd211b958;

/// adnl.address.udp ip:int port:int
pub const ADNL_ADDRESS_UDP: u32 = 0x670da6e7;

/// adnl.address.udp6 ip:int128 port:int
pub const ADNL_ADDRESS_UDP6: u32 = 0xe31d63fa;

/// pub.ed25519 key:int256 = PublicKey
pub const PUB_ED25519: u32 = 0x4813b4c6;

// ============================================================================
// TL Writer
// ============================================================================

/// A helper for building TL messages.
#[derive(Default)]
pub struct TlWriter {
    buffer: Vec<u8>,
}

impl TlWriter {
    /// Creates a new TL writer.
    pub fn new() -> Self {
        Self { buffer: Vec::new() }
    }

    /// Creates a new TL writer with pre-allocated capacity.
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            buffer: Vec::with_capacity(capacity),
        }
    }

    /// Writes raw bytes without encoding.
    pub fn write_raw(&mut self, data: &[u8]) -> &mut Self {
        self.buffer.extend_from_slice(data);
        self
    }

    /// Writes a u32 value in little-endian.
    pub fn write_u32(&mut self, value: u32) -> &mut Self {
        self.buffer.extend_from_slice(&value.to_le_bytes());
        self
    }

    /// Writes an i32 value in little-endian.
    pub fn write_i32(&mut self, value: i32) -> &mut Self {
        self.buffer.extend_from_slice(&value.to_le_bytes());
        self
    }

    /// Writes a u64 value in little-endian.
    pub fn write_u64(&mut self, value: u64) -> &mut Self {
        self.buffer.extend_from_slice(&value.to_le_bytes());
        self
    }

    /// Writes an i64 value in little-endian.
    pub fn write_i64(&mut self, value: i64) -> &mut Self {
        self.buffer.extend_from_slice(&value.to_le_bytes());
        self
    }

    /// Writes a 256-bit integer (32 bytes).
    pub fn write_int256(&mut self, value: &[u8; 32]) -> &mut Self {
        self.buffer.extend_from_slice(value);
        self
    }

    /// Writes bytes with TL encoding.
    ///
    /// TL byte encoding:
    /// - If length < 254: 1 byte length prefix, then data, then padding to 4-byte boundary
    /// - If length >= 254: 0xFE marker, 3 bytes length (LE), then data, then padding
    pub fn write_bytes(&mut self, data: &[u8]) -> &mut Self {
        let len = data.len();

        if len < 254 {
            // Short encoding: 1 byte length + data + padding
            self.buffer.push(len as u8);
            self.buffer.extend_from_slice(data);

            let total = 1 + len;
            let padding = (4 - (total % 4)) % 4;
            self.buffer.extend(std::iter::repeat_n(0, padding));
        } else {
            // Long encoding: 0xFE + 3 bytes length + data + padding
            self.buffer.push(0xFE);
            self.buffer.push((len & 0xFF) as u8);
            self.buffer.push(((len >> 8) & 0xFF) as u8);
            self.buffer.push(((len >> 16) & 0xFF) as u8);
            self.buffer.extend_from_slice(data);

            let total = 4 + len;
            let padding = (4 - (total % 4)) % 4;
            self.buffer.extend(std::iter::repeat_n(0, padding));
        }

        self
    }

    /// Returns the current length of the buffer.
    pub fn len(&self) -> usize {
        self.buffer.len()
    }

    /// Returns true if the buffer is empty.
    pub fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }

    /// Consumes the writer and returns the buffer.
    pub fn finish(self) -> Vec<u8> {
        self.buffer
    }

    /// Returns a reference to the current buffer.
    pub fn as_bytes(&self) -> &[u8] {
        &self.buffer
    }
}

// ============================================================================
// TL Reader
// ============================================================================

/// A helper for reading TL messages.
pub struct TlReader<'a> {
    data: &'a [u8],
    offset: usize,
}

impl<'a> TlReader<'a> {
    /// Creates a new TL reader.
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, offset: 0 }
    }

    /// Returns the remaining unread data.
    pub fn remaining(&self) -> &[u8] {
        &self.data[self.offset..]
    }

    /// Returns the number of bytes remaining.
    pub fn remaining_len(&self) -> usize {
        self.data.len() - self.offset
    }

    /// Returns the current offset.
    pub fn offset(&self) -> usize {
        self.offset
    }

    /// Returns true if there's no more data to read.
    pub fn is_empty(&self) -> bool {
        self.offset >= self.data.len()
    }

    /// Reads raw bytes without decoding.
    pub fn read_raw(&mut self, len: usize) -> Result<&'a [u8]> {
        if self.remaining_len() < len {
            return Err(DhtError::TlError(format!(
                "need {} bytes, have {}",
                len,
                self.remaining_len()
            )));
        }
        let result = &self.data[self.offset..self.offset + len];
        self.offset += len;
        Ok(result)
    }

    /// Reads a u32 value.
    pub fn read_u32(&mut self) -> Result<u32> {
        let bytes = self.read_raw(4)?;
        Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    /// Reads an i32 value.
    pub fn read_i32(&mut self) -> Result<i32> {
        let bytes = self.read_raw(4)?;
        Ok(i32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    /// Reads a u64 value.
    pub fn read_u64(&mut self) -> Result<u64> {
        let bytes = self.read_raw(8)?;
        Ok(u64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]))
    }

    /// Reads an i64 value.
    pub fn read_i64(&mut self) -> Result<i64> {
        let bytes = self.read_raw(8)?;
        Ok(i64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]))
    }

    /// Reads a 256-bit integer (32 bytes).
    pub fn read_int256(&mut self) -> Result<[u8; 32]> {
        let bytes = self.read_raw(32)?;
        let mut result = [0u8; 32];
        result.copy_from_slice(bytes);
        Ok(result)
    }

    /// Reads TL-encoded bytes.
    pub fn read_bytes(&mut self) -> Result<Vec<u8>> {
        if self.remaining_len() < 1 {
            return Err(DhtError::TlError("need at least 1 byte".into()));
        }

        let first_byte = self.data[self.offset];

        if first_byte < 254 {
            // Short encoding
            let len = first_byte as usize;
            let total = 1 + len;
            let padding = (4 - (total % 4)) % 4;
            let consumed = total + padding;

            if self.remaining_len() < consumed {
                return Err(DhtError::TlError(format!(
                    "need {} bytes, have {}",
                    consumed,
                    self.remaining_len()
                )));
            }

            let result = self.data[self.offset + 1..self.offset + 1 + len].to_vec();
            self.offset += consumed;
            Ok(result)
        } else {
            // Long encoding (first byte == 0xFE)
            if self.remaining_len() < 4 {
                return Err(DhtError::TlError(
                    "need at least 4 bytes for long encoding".into(),
                ));
            }

            let len = (self.data[self.offset + 1] as usize)
                | ((self.data[self.offset + 2] as usize) << 8)
                | ((self.data[self.offset + 3] as usize) << 16);

            let total = 4 + len;
            let padding = (4 - (total % 4)) % 4;
            let consumed = total + padding;

            if self.remaining_len() < consumed {
                return Err(DhtError::TlError(format!(
                    "need {} bytes, have {}",
                    consumed,
                    self.remaining_len()
                )));
            }

            let result = self.data[self.offset + 4..self.offset + 4 + len].to_vec();
            self.offset += consumed;
            Ok(result)
        }
    }

    /// Peeks at the next u32 without consuming it.
    pub fn peek_u32(&self) -> Result<u32> {
        if self.remaining_len() < 4 {
            return Err(DhtError::TlError("need 4 bytes to peek".into()));
        }
        let bytes = &self.data[self.offset..self.offset + 4];
        Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    /// Skips the specified number of bytes.
    pub fn skip(&mut self, len: usize) -> Result<()> {
        if self.remaining_len() < len {
            return Err(DhtError::TlError(format!(
                "cannot skip {} bytes, only {} remaining",
                len,
                self.remaining_len()
            )));
        }
        self.offset += len;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_writer_u32() {
        let mut writer = TlWriter::new();
        writer.write_u32(0x12345678);
        assert_eq!(writer.finish(), vec![0x78, 0x56, 0x34, 0x12]);
    }

    #[test]
    fn test_writer_i32() {
        let mut writer = TlWriter::new();
        writer.write_i32(-1);
        assert_eq!(writer.finish(), vec![0xFF, 0xFF, 0xFF, 0xFF]);
    }

    #[test]
    fn test_writer_bytes_short() {
        let mut writer = TlWriter::new();
        writer.write_bytes(b"Hi");
        let result = writer.finish();

        assert_eq!(result[0], 2); // Length
        assert_eq!(&result[1..3], b"Hi");
        assert_eq!(result.len() % 4, 0); // Aligned
    }

    #[test]
    fn test_writer_bytes_long() {
        let data: Vec<u8> = (0..300).map(|i| i as u8).collect();
        let mut writer = TlWriter::new();
        writer.write_bytes(&data);
        let result = writer.finish();

        assert_eq!(result[0], 0xFE);
        assert_eq!(result[1], 0x2C); // 300 & 0xFF
        assert_eq!(result[2], 0x01); // (300 >> 8) & 0xFF
        assert_eq!(result[3], 0x00);
        assert_eq!(&result[4..304], &data[..]);
        assert_eq!(result.len() % 4, 0);
    }

    #[test]
    fn test_reader_u32() {
        let data = [0x78, 0x56, 0x34, 0x12];
        let mut reader = TlReader::new(&data);
        assert_eq!(reader.read_u32().unwrap(), 0x12345678);
    }

    #[test]
    fn test_reader_bytes_roundtrip() {
        let original = b"Hello, DHT!";
        let mut writer = TlWriter::new();
        writer.write_bytes(original);
        let encoded = writer.finish();

        let mut reader = TlReader::new(&encoded);
        let decoded = reader.read_bytes().unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn test_int256_roundtrip() {
        let value = [42u8; 32];
        let mut writer = TlWriter::new();
        writer.write_int256(&value);
        let data = writer.finish();

        let mut reader = TlReader::new(&data);
        let result = reader.read_int256().unwrap();
        assert_eq!(result, value);
    }

    #[test]
    fn test_schema_ids() {
        // Verify some important schema IDs
        assert_eq!(DHT_FIND_VALUE, 0xa8f51e79);
        assert_eq!(DHT_FIND_NODE, 0x47bf71fd);
        assert_eq!(DHT_STORE, 0x29c40d72);
        assert_eq!(DHT_PING, 0x75b0fc25);
        assert_eq!(DHT_UPDATE_RULE_SIGNATURE, 0x10b5b3cc);
        assert_eq!(DHT_UPDATE_RULE_ANYBODY, 0xd7e6c0f7);
    }
}
