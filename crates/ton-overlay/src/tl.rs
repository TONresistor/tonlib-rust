//! TL (Type Language) schemas and utilities for Overlay Network.
//!
//! This module provides TL schema IDs and serialization helpers for overlay messages.

use crate::error::{OverlayError, Result};

// ============================================================================
// Overlay TL Schema IDs (CRC32 of schema definitions)
// ============================================================================

/// overlay.node id:PublicKey overlay:int256 version:int signature:bytes = overlay.Node
pub const OVERLAY_NODE: u32 = 0xd8f89b1c;

/// overlay.nodes nodes:(vector overlay.node) = overlay.Nodes
pub const OVERLAY_NODES: u32 = 0x66f1e9f0;

/// overlay.query overlay:int256 = True
/// Used as prefix for all overlay queries
pub const OVERLAY_QUERY: u32 = 0x4ad47b01;

/// overlay.getRandomPeers peers:overlay.nodes = overlay.Nodes
pub const OVERLAY_GET_RANDOM_PEERS: u32 = 0xda9d6ed1;

/// overlay.broadcast src:PublicKey certificate:overlay.Certificate flags:int data:bytes date:int signature:bytes = overlay.Broadcast
pub const OVERLAY_BROADCAST: u32 = 0xa8b7e06c;

/// overlay.broadcastFec src:PublicKey certificate:overlay.Certificate data_hash:int256 data_size:int flags:int data:bytes seqno:int fec:fec.Type date:int signature:bytes = overlay.Broadcast
pub const OVERLAY_BROADCAST_FEC: u32 = 0x07956eb9;

/// overlay.broadcastFecShort src:PublicKey certificate:overlay.Certificate broadcast_hash:int256 part_data_hash:int256 seqno:int signature:bytes = overlay.Broadcast
pub const OVERLAY_BROADCAST_FEC_SHORT: u32 = 0x0a9ef4c8;

/// overlay.broadcastFecConfirm hash:int256 seqno:int = overlay.BroadcastFecConfirm
pub const OVERLAY_BROADCAST_FEC_CONFIRM: u32 = 0x5c1bb3e6;

/// overlay.broadcastNotFound = overlay.Broadcast
pub const OVERLAY_BROADCAST_NOT_FOUND: u32 = 0x7d1c9f3a;

/// overlay.broadcast.toSign hash:int256 date:int = overlay.Broadcast.ToSign
/// Used for computing signature data for broadcasts (NOT the message schema)
pub const OVERLAY_BROADCAST_TO_SIGN: u32 = 0xb22ac4e5;

/// overlay.broadcastFec.id src:int256 type:int256 data_hash:int256 size:int flags:int = overlay.broadcastFec.Id
/// Used for FEC broadcast ID calculation
pub const OVERLAY_BROADCAST_FEC_ID: u32 = 0x79c9d5e1;

/// overlay.broadcastFec.partId broadcast_hash:int256 data_hash:int256 seqno:int = overlay.broadcastFec.PartId
/// Used for FEC part ID calculation
pub const OVERLAY_BROADCAST_FEC_PART_ID: u32 = 0xf2c4d1a3;

/// overlay.node.toSign id:adnl.id.short overlay:int256 version:int = overlay.Node.ToSign
/// Used for computing signature data for nodes (NOT the message schema)
pub const OVERLAY_NODE_TO_SIGN: u32 = 0x5f5b30e7;

/// overlay.certificate issued_by:PublicKey expire_at:int max_size:int signature:bytes = overlay.Certificate
pub const OVERLAY_CERTIFICATE: u32 = 0xa0d1db3e;

/// overlay.emptyCertificate = overlay.Certificate
pub const OVERLAY_EMPTY_CERTIFICATE: u32 = 0x8b0c0c35;

/// overlay.certificateId overlay_id:int256 node:int256 expire_at:int max_size:int = overlay.CertificateId
pub const OVERLAY_CERTIFICATE_ID: u32 = 0x1c3b9e2a;

/// overlay.message overlay:int256 = overlay.Message
pub const OVERLAY_MESSAGE: u32 = 0x3d7c8b1f;

/// overlay.broadcastList hashes:(vector int256) = overlay.BroadcastList
pub const OVERLAY_BROADCAST_LIST: u32 = 0x5ea0f9c2;

/// overlay.fec.received hash:int256 = overlay.Received
pub const OVERLAY_FEC_RECEIVED: u32 = 0x4c2a7b3d;

/// overlay.fec.completed hash:int256 = overlay.Completed
pub const OVERLAY_FEC_COMPLETED: u32 = 0x7e9b3a1c;

// ============================================================================
// tonNode TL Schema IDs (for overlay ID calculation)
// ============================================================================

/// tonNode.shardPublicOverlayId workchain:int shard:long zero_state_file_hash:int256 = tonNode.ShardPublicOverlayId
pub const TON_NODE_SHARD_PUBLIC_OVERLAY_ID: u32 = 0x8a8e6c2c;

// ============================================================================
// PublicKey TL Schema IDs
// ============================================================================

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

    /// Writes a vector of items using a provided serializer function.
    pub fn write_vector<T, F>(&mut self, items: &[T], serialize: F) -> &mut Self
    where
        F: Fn(&mut TlWriter, &T),
    {
        self.write_u32(items.len() as u32);
        for item in items {
            serialize(self, item);
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
            return Err(OverlayError::TlError(format!(
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
            return Err(OverlayError::TlError("need at least 1 byte".into()));
        }

        let first_byte = self.data[self.offset];

        if first_byte < 254 {
            // Short encoding
            let len = first_byte as usize;
            let total = 1 + len;
            let padding = (4 - (total % 4)) % 4;
            let consumed = total + padding;

            if self.remaining_len() < consumed {
                return Err(OverlayError::TlError(format!(
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
                return Err(OverlayError::TlError(
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
                return Err(OverlayError::TlError(format!(
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

    /// Reads a vector length and returns it.
    pub fn read_vector_len(&mut self) -> Result<u32> {
        self.read_u32()
    }

    /// Peeks at the next u32 without consuming it.
    pub fn peek_u32(&self) -> Result<u32> {
        if self.remaining_len() < 4 {
            return Err(OverlayError::TlError("need 4 bytes to peek".into()));
        }
        let bytes = &self.data[self.offset..self.offset + 4];
        Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    /// Skips the specified number of bytes.
    pub fn skip(&mut self, len: usize) -> Result<()> {
        if self.remaining_len() < len {
            return Err(OverlayError::TlError(format!(
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
    fn test_writer_i64() {
        let mut writer = TlWriter::new();
        writer.write_i64(0x123456789ABCDEF0i64);
        assert_eq!(
            writer.finish(),
            vec![0xF0, 0xDE, 0xBC, 0x9A, 0x78, 0x56, 0x34, 0x12]
        );
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
        let original = b"Hello, Overlay!";
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
        // Verify schema IDs are valid
        assert_eq!(OVERLAY_NODE, 0xd8f89b1c);
        assert_eq!(OVERLAY_NODES, 0x66f1e9f0);
        assert_eq!(OVERLAY_QUERY, 0x4ad47b01);
        assert_eq!(OVERLAY_GET_RANDOM_PEERS, 0xda9d6ed1);
        assert_eq!(OVERLAY_BROADCAST, 0xa8b7e06c);
        assert_eq!(OVERLAY_CERTIFICATE, 0xa0d1db3e);
        assert_eq!(OVERLAY_EMPTY_CERTIFICATE, 0x8b0c0c35);
        assert_eq!(TON_NODE_SHARD_PUBLIC_OVERLAY_ID, 0x8a8e6c2c);
    }
}
