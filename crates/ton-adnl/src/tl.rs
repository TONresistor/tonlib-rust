//! TL (Type Language) encoding/decoding utilities for ADNL.
//!
//! This module provides basic TL serialization primitives needed for ADNL.
//! It implements enough TL support to handle ADNL protocol messages without
//! depending on a full TL implementation.

use crate::error::{AdnlError, Result};

// ============================================================================
// TL Schema IDs (CRC32 of schema definitions)
// ============================================================================

/// tcp.ping random_id:long = tcp.Pong
pub const TCP_PING: u32 = 0x9a2b084d;

/// tcp.pong random_id:long = tcp.Pong
pub const TCP_PONG: u32 = 0x4f15c5d8;

/// adnl.message.query query_id:int256 query:bytes = adnl.Message
pub const ADNL_MESSAGE_QUERY: u32 = 0x7af98bb4;

/// adnl.message.answer query_id:int256 answer:bytes = adnl.Message
pub const ADNL_MESSAGE_ANSWER: u32 = 0x1684ac0f;

/// adnl.message.custom data:bytes = adnl.Message
pub const ADNL_MESSAGE_CUSTOM: u32 = 0xca3f6fe0;

/// liteServer.query data:bytes = Object
pub const LITESERVER_QUERY: u32 = 0xdf068c79;

/// pub.ed25519 key:int256 = PublicKey
pub const PUB_ED25519: u32 = 0x4813b4c6;

/// liteServer.getMasterchainInfo = liteServer.MasterchainInfo
/// NOTE: Use TL_LITE_GET_MASTERCHAIN_INFO from lite_tl.rs instead
pub const LITESERVER_GET_MASTERCHAIN_INFO: u32 = 0x89b5e62e;

/// liteServer.getTime = liteServer.CurrentTime
/// NOTE: Use TL_LITE_GET_TIME from lite_tl.rs instead
pub const LITESERVER_GET_TIME: u32 = 0x16ad5a34;

// ============================================================================
// ADNL UDP Schema IDs
// ============================================================================

/// adnl.message.createChannel key:int256 date:int = adnl.Message
pub const ADNL_CREATE_CHANNEL: u32 = 0xbbc373e6;

/// adnl.message.confirmChannel key:int256 peer_key:int256 date:int = adnl.Message
pub const ADNL_CONFIRM_CHANNEL: u32 = 0xd66d6f6e;

/// adnl.message.part hash:int256 total_size:int offset:int data:bytes = adnl.Message
pub const ADNL_MESSAGE_PART: u32 = 0xfec8f8a4;

/// adnl.message.nop = adnl.Message
/// No-operation message for keepalive purposes.
#[allow(dead_code)]
pub const ADNL_MESSAGE_NOP: u32 = 0x02b46e5e;

/// adnl.message.reinit date:int = adnl.Message
/// Reinitialize connection message.
#[allow(dead_code)]
pub const ADNL_MESSAGE_REINIT: u32 = 0x10c20520;

/// adnl.packetContents = adnl.PacketContents
pub const ADNL_PACKET_CONTENTS: u32 = 0xd142cd89;

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

    /// Writes a 128-bit integer (16 bytes).
    pub fn write_int128(&mut self, value: &[u8; 16]) -> &mut Self {
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
            return Err(AdnlError::TlError(format!(
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
            bytes[0], bytes[1], bytes[2], bytes[3],
            bytes[4], bytes[5], bytes[6], bytes[7],
        ]))
    }

    /// Reads an i64 value.
    pub fn read_i64(&mut self) -> Result<i64> {
        let bytes = self.read_raw(8)?;
        Ok(i64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3],
            bytes[4], bytes[5], bytes[6], bytes[7],
        ]))
    }

    /// Reads a 256-bit integer (32 bytes).
    pub fn read_int256(&mut self) -> Result<[u8; 32]> {
        let bytes = self.read_raw(32)?;
        let mut result = [0u8; 32];
        result.copy_from_slice(bytes);
        Ok(result)
    }

    /// Reads a 128-bit integer (16 bytes).
    pub fn read_int128(&mut self) -> Result<[u8; 16]> {
        let bytes = self.read_raw(16)?;
        let mut result = [0u8; 16];
        result.copy_from_slice(bytes);
        Ok(result)
    }

    /// Reads TL-encoded bytes.
    pub fn read_bytes(&mut self) -> Result<Vec<u8>> {
        if self.remaining_len() < 1 {
            return Err(AdnlError::TlError("need at least 1 byte".into()));
        }

        let first_byte = self.data[self.offset];

        if first_byte < 254 {
            // Short encoding
            let len = first_byte as usize;
            let total = 1 + len;
            let padding = (4 - (total % 4)) % 4;
            let consumed = total + padding;

            if self.remaining_len() < consumed {
                return Err(AdnlError::TlError(format!(
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
                return Err(AdnlError::TlError("need at least 4 bytes for long encoding".into()));
            }

            let len = (self.data[self.offset + 1] as usize)
                | ((self.data[self.offset + 2] as usize) << 8)
                | ((self.data[self.offset + 3] as usize) << 16);

            let total = 4 + len;
            let padding = (4 - (total % 4)) % 4;
            let consumed = total + padding;

            if self.remaining_len() < consumed {
                return Err(AdnlError::TlError(format!(
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
            return Err(AdnlError::TlError("need 4 bytes to peek".into()));
        }
        let bytes = &self.data[self.offset..self.offset + 4];
        Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    /// Skips the specified number of bytes.
    pub fn skip(&mut self, len: usize) -> Result<()> {
        if self.remaining_len() < len {
            return Err(AdnlError::TlError(format!(
                "cannot skip {} bytes, only {} remaining",
                len,
                self.remaining_len()
            )));
        }
        self.offset += len;
        Ok(())
    }
}

// ============================================================================
// Helper functions
// ============================================================================

/// Encodes bytes using TL byte encoding.
pub fn encode_bytes(data: &[u8]) -> Vec<u8> {
    let mut writer = TlWriter::new();
    writer.write_bytes(data);
    writer.finish()
}

/// Decodes TL-encoded bytes.
///
/// Returns the decoded bytes and the number of bytes consumed.
pub fn decode_bytes(data: &[u8]) -> Result<(Vec<u8>, usize)> {
    let mut reader = TlReader::new(data);
    let bytes = reader.read_bytes()?;
    Ok((bytes, reader.offset()))
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
    fn test_writer_u64() {
        let mut writer = TlWriter::new();
        writer.write_u64(0x123456789ABCDEF0);
        assert_eq!(writer.finish(), vec![0xF0, 0xDE, 0xBC, 0x9A, 0x78, 0x56, 0x34, 0x12]);
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
    fn test_reader_bytes_short() {
        let mut writer = TlWriter::new();
        writer.write_bytes(b"Hello");
        let data = writer.finish();

        let mut reader = TlReader::new(&data);
        let bytes = reader.read_bytes().unwrap();
        assert_eq!(bytes, b"Hello");
    }

    #[test]
    fn test_reader_bytes_long() {
        let original: Vec<u8> = (0..300).map(|i| i as u8).collect();
        let mut writer = TlWriter::new();
        writer.write_bytes(&original);
        let data = writer.finish();

        let mut reader = TlReader::new(&data);
        let bytes = reader.read_bytes().unwrap();
        assert_eq!(bytes, original);
    }

    #[test]
    fn test_encode_decode_roundtrip() {
        for len in 0..500 {
            let original: Vec<u8> = (0..len).map(|i| (i % 256) as u8).collect();
            let encoded = encode_bytes(&original);
            let (decoded, _) = decode_bytes(&encoded).unwrap();
            assert_eq!(decoded, original, "Failed for length {}", len);
        }
    }

    #[test]
    fn test_int256() {
        let value = [42u8; 32];
        let mut writer = TlWriter::new();
        writer.write_int256(&value);
        let data = writer.finish();

        let mut reader = TlReader::new(&data);
        let result = reader.read_int256().unwrap();
        assert_eq!(result, value);
    }

    #[test]
    fn test_complex_message() {
        let mut writer = TlWriter::new();
        writer.write_u32(TCP_PING);
        writer.write_u64(12345);
        let data = writer.finish();

        let mut reader = TlReader::new(&data);
        assert_eq!(reader.read_u32().unwrap(), TCP_PING);
        assert_eq!(reader.read_u64().unwrap(), 12345);
        assert!(reader.is_empty());
    }
}
