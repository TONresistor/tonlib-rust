//! Forward Error Correction (FEC) implementation using RaptorQ.
//!
//! This module provides FEC encoding and decoding for reliable data transfer
//! over unreliable channels. It uses RaptorQ fountain codes which allow
//! the receiver to reconstruct the original data from any sufficient subset
//! of encoded symbols.
//!
//! ## Overview
//!
//! RaptorQ is a fountain code that:
//! - Encodes data into an unlimited number of "repair symbols"
//! - Can recover original data from any K' symbols (where K' is slightly more than K)
//! - Tolerates arbitrary packet loss patterns
//!
//! ## Usage
//!
//! ```rust
//! use ton_rldp::fec::{FecEncoder, FecDecoder, SYMBOL_SIZE};
//!
//! // Encoding
//! let data = b"Hello, RLDP! This is test data for FEC encoding.";
//! let encoder = FecEncoder::new(data);
//! let packets = encoder.encode_all(5); // 5 extra repair symbols
//!
//! // Decoding (can recover from any sufficient subset)
//! let mut decoder = FecDecoder::new(data.len(), SYMBOL_SIZE);
//! for (seqno, packet) in packets.iter() {
//!     if decoder.add_packet(packet) {
//!         break; // Decoding complete
//!     }
//! }
//! let recovered = decoder.decode().unwrap();
//! assert_eq!(recovered, data);
//! ```

use raptorq::{Decoder, Encoder, EncodingPacket, ObjectTransmissionInformation};

use crate::error::{RldpError, Result};
use crate::types::FecType;

/// Default symbol size in bytes.
/// This is the standard symbol size used in TON RLDP.
/// Each FEC-encoded symbol is 768 bytes.
pub const SYMBOL_SIZE: usize = 768;

/// Maximum datagram slice size in bytes.
/// This is the maximum size of data that can fit in a single RLDP message part.
/// Official TON RLDP uses 2048 bytes.
pub const SLICE_SIZE: usize = 2048;

/// Sliding window size for FEC packet sending.
/// This controls how many packets can be in-flight before waiting for confirmation.
/// Official TON RLDP uses a window of 1000 packets.
pub const WINDOW_SIZE: usize = 1000;

/// FEC encoder using RaptorQ.
///
/// Encodes data into symbols that can be used to reconstruct the original
/// data even with packet loss.
#[derive(Clone)]
pub struct FecEncoder {
    encoder: Encoder,
    data_size: usize,
    symbol_size: usize,
    symbols_count: usize,
}

impl FecEncoder {
    /// Creates a new FEC encoder for the given data.
    ///
    /// Uses the default symbol size of 768 bytes.
    pub fn new(data: &[u8]) -> Self {
        Self::with_symbol_size(data, SYMBOL_SIZE)
    }

    /// Creates a new FEC encoder with a custom symbol size.
    pub fn with_symbol_size(data: &[u8], symbol_size: usize) -> Self {
        let data_size = data.len();

        // Handle empty data
        if data_size == 0 {
            return Self {
                encoder: Encoder::with_defaults(&[0u8], symbol_size as u16),
                data_size: 0,
                symbol_size,
                symbols_count: 0,
            };
        }

        // Create the RaptorQ encoder
        let encoder = Encoder::with_defaults(data, symbol_size as u16);

        // Get actual symbols count from encoder
        let symbols_count = encoder
            .get_block_encoders()
            .first()
            .map(|b| b.source_packets().len())
            .unwrap_or(1);

        Self {
            encoder,
            data_size,
            symbol_size,
            symbols_count,
        }
    }

    /// Returns the original data size.
    pub fn data_size(&self) -> usize {
        self.data_size
    }

    /// Returns the symbol size.
    pub fn symbol_size(&self) -> usize {
        self.symbol_size
    }

    /// Returns the number of source symbols (before repair symbols).
    pub fn symbols_count(&self) -> usize {
        self.symbols_count
    }

    /// Returns the FEC type for this encoder.
    pub fn fec_type(&self) -> FecType {
        FecType::raptorq(
            self.data_size as i32,
            self.symbol_size as i32,
            self.symbols_count as i32,
        )
    }

    /// Validates that the FEC type is supported (RaptorQ only).
    ///
    /// Official TON RLDP only supports RaptorQ. RoundRobin and Online are
    /// experimental and not fully implemented. This function ensures we fail
    /// fast with clear error messages rather than silently degrading.
    pub fn validate_fec_type(fec_type: &FecType) -> Result<()> {
        match fec_type {
            FecType::RaptorQ { .. } => Ok(()),
            FecType::RoundRobin { .. } => {
                Err(RldpError::UnsupportedFecType(
                    "RoundRobin FEC type is not yet supported (experimental)".to_string(),
                ))
            }
            FecType::Online { .. } => {
                Err(RldpError::UnsupportedFecType(
                    "Online FEC type is not yet supported (experimental)".to_string(),
                ))
            }
        }
    }

    /// Encodes all source symbols plus the specified number of repair symbols.
    ///
    /// Returns a vector of (seqno, serialized_packet) pairs.
    /// The serialized packet includes all metadata needed for decoding.
    pub fn encode_all(&self, repair_count: u32) -> Vec<(u32, Vec<u8>)> {
        if self.data_size == 0 {
            return Vec::new();
        }

        let blocks = self.encoder.get_block_encoders();

        if blocks.is_empty() {
            return Vec::new();
        }

        let block = &blocks[0];
        let mut result = Vec::new();

        // Get source symbols
        let source_packets = block.source_packets();
        for (i, packet) in source_packets.into_iter().enumerate() {
            result.push((i as u32, packet.serialize()));
        }

        // Get repair symbols
        if repair_count > 0 {
            let repair_packets = block.repair_packets(0, repair_count);
            for (i, packet) in repair_packets.into_iter().enumerate() {
                result.push((self.symbols_count as u32 + i as u32, packet.serialize()));
            }
        }

        result
    }

    /// Generates a single repair packet at the given index.
    ///
    /// Returns the serialized packet.
    pub fn encode_repair(&self, repair_index: u32) -> Option<Vec<u8>> {
        if self.data_size == 0 {
            return None;
        }

        let blocks = self.encoder.get_block_encoders();
        if blocks.is_empty() {
            return None;
        }

        let block = &blocks[0];
        let packets = block.repair_packets(repair_index, 1);
        packets.into_iter().next().map(|p| p.serialize())
    }

    /// Returns an iterator that generates packets on demand.
    pub fn packet_iter(&self) -> FecEncoderIter {
        FecEncoderIter {
            encoder: self.clone(),
            current_index: 0,
        }
    }
}

impl std::fmt::Debug for FecEncoder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FecEncoder")
            .field("data_size", &self.data_size)
            .field("symbol_size", &self.symbol_size)
            .field("symbols_count", &self.symbols_count)
            .finish()
    }
}

/// Iterator over FEC-encoded packets.
pub struct FecEncoderIter {
    encoder: FecEncoder,
    current_index: u32,
}

impl Iterator for FecEncoderIter {
    type Item = (u32, Vec<u8>);

    fn next(&mut self) -> Option<Self::Item> {
        if self.encoder.data_size == 0 {
            return None;
        }

        let index = self.current_index;
        self.current_index += 1;

        // First return source packets, then repair packets
        let blocks = self.encoder.encoder.get_block_encoders();
        if blocks.is_empty() {
            return None;
        }

        let block = &blocks[0];

        if (index as usize) < self.encoder.symbols_count {
            // Source packet
            let source_packets = block.source_packets();
            source_packets
                .into_iter()
                .nth(index as usize)
                .map(|p| (index, p.serialize()))
        } else {
            // Repair packet
            let repair_index = index - self.encoder.symbols_count as u32;
            let packets = block.repair_packets(repair_index, 1);
            packets.into_iter().next().map(|p| (index, p.serialize()))
        }
    }
}

/// FEC decoder using RaptorQ.
///
/// Accumulates received packets and attempts to reconstruct the original data.
#[derive(Debug)]
pub struct FecDecoder {
    decoder: Decoder,
    data_size: usize,
    symbol_size: usize,
    packets_received: usize,
    is_complete: bool,
    decoded_data: Option<Vec<u8>>,
}

impl FecDecoder {
    /// Creates a new FEC decoder.
    ///
    /// # Arguments
    ///
    /// * `data_size` - The original data size in bytes
    /// * `symbol_size` - The symbol size used for encoding
    pub fn new(data_size: usize, symbol_size: usize) -> Self {
        // Handle empty data
        if data_size == 0 {
            return Self {
                decoder: Decoder::new(ObjectTransmissionInformation::with_defaults(1, symbol_size as u16)),
                data_size: 0,
                symbol_size,
                packets_received: 0,
                is_complete: true,
                decoded_data: Some(Vec::new()),
            };
        }

        let oti = ObjectTransmissionInformation::with_defaults(data_size as u64, symbol_size as u16);
        let decoder = Decoder::new(oti);

        Self {
            decoder,
            data_size,
            symbol_size,
            packets_received: 0,
            is_complete: false,
            decoded_data: None,
        }
    }

    /// Creates a decoder from a FecType.
    pub fn from_fec_type(fec_type: &FecType) -> Result<Self> {
        match fec_type {
            FecType::RaptorQ {
                data_size,
                symbol_size,
                ..
            } => Ok(Self::new(*data_size as usize, *symbol_size as usize)),
            _ => Err(RldpError::UnsupportedFecType(
                "Only RaptorQ FEC type is supported".to_string(),
            )),
        }
    }

    /// Returns the original data size.
    pub fn data_size(&self) -> usize {
        self.data_size
    }

    /// Returns the symbol size.
    pub fn symbol_size(&self) -> usize {
        self.symbol_size
    }

    /// Returns the number of packets received so far.
    pub fn packets_received(&self) -> usize {
        self.packets_received
    }

    /// Alias for packets_received for API compatibility.
    pub fn symbols_received(&self) -> usize {
        self.packets_received
    }

    /// Returns true if decoding is complete.
    pub fn is_complete(&self) -> bool {
        self.is_complete
    }

    /// Adds a received serialized packet to the decoder.
    ///
    /// The packet should be the serialized form from FecEncoder.
    /// Returns `true` if decoding is now complete, `false` otherwise.
    pub fn add_packet(&mut self, packet_data: &[u8]) -> bool {
        if self.is_complete {
            return true;
        }

        self.packets_received += 1;

        // Deserialize the packet
        let packet = EncodingPacket::deserialize(packet_data);

        // Try to decode
        if let Some(decoded) = self.decoder.decode(packet) {
            let mut result = decoded;
            result.truncate(self.data_size);
            self.decoded_data = Some(result);
            self.is_complete = true;
            return true;
        }

        false
    }

    /// Adds a received symbol to the decoder (compatibility alias).
    ///
    /// The seqno parameter is ignored as the packet contains its own metadata.
    pub fn add_symbol(&mut self, _seqno: u32, packet_data: &[u8]) -> bool {
        self.add_packet(packet_data)
    }

    /// Attempts to decode the data from received packets.
    ///
    /// Returns the decoded data if successful, or an error if not enough
    /// packets have been received.
    pub fn decode(&self) -> Result<Vec<u8>> {
        self.decoded_data
            .clone()
            .ok_or(RldpError::InsufficientSymbols {
                received: self.packets_received,
                needed: (self.data_size + self.symbol_size - 1) / self.symbol_size.max(1),
            })
    }

    /// Takes the decoded data, consuming it.
    pub fn take_decoded(&mut self) -> Result<Vec<u8>> {
        self.decoded_data.take().ok_or(RldpError::InsufficientSymbols {
            received: self.packets_received,
            needed: (self.data_size + self.symbol_size - 1) / self.symbol_size.max(1),
        })
    }
}

/// Convenience function to encode data for RLDP transfer.
///
/// Returns the FEC type and all packets (source + repair).
pub fn encode_for_transfer(data: &[u8], repair_ratio: f32) -> (FecType, Vec<(u32, Vec<u8>)>) {
    let encoder = FecEncoder::new(data);
    let repair_count = ((encoder.symbols_count() as f32 * repair_ratio).ceil() as u32).max(1);
    let packets = encoder.encode_all(repair_count);
    (encoder.fec_type(), packets)
}

/// Convenience function to decode data from received packets.
pub fn decode_from_symbols(
    fec_type: &FecType,
    packets: impl IntoIterator<Item = (u32, Vec<u8>)>,
) -> Result<Vec<u8>> {
    let mut decoder = FecDecoder::from_fec_type(fec_type)?;

    for (_seqno, data) in packets {
        if decoder.add_packet(&data) {
            return decoder.decode();
        }
    }

    decoder.decode()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encoder_creation() {
        let data = b"Hello, RLDP!";
        let encoder = FecEncoder::new(data);

        assert_eq!(encoder.data_size(), data.len());
        assert_eq!(encoder.symbol_size(), SYMBOL_SIZE);
        assert!(encoder.symbols_count() >= 1);
    }

    #[test]
    fn test_validate_fec_type_raptorq() {
        // RaptorQ should be accepted
        let fec_type = FecType::RaptorQ {
            data_size: 100,
            symbol_size: 768,
            symbols_count: 5,
        };
        assert!(FecEncoder::validate_fec_type(&fec_type).is_ok());
    }

    #[test]
    fn test_validate_fec_type_roundrobin() {
        // RoundRobin should be rejected with clear error
        let fec_type = FecType::RoundRobin {
            data_size: 100,
            symbol_size: 768,
            symbols_count: 5,
        };
        let result = FecEncoder::validate_fec_type(&fec_type);

        assert!(result.is_err());
        match result {
            Err(RldpError::UnsupportedFecType(msg)) => {
                assert!(msg.contains("RoundRobin"));
            }
            _ => panic!("Expected UnsupportedFecType error"),
        }
    }

    #[test]
    fn test_validate_fec_type_online() {
        // Online should be rejected with clear error
        let fec_type = FecType::Online {
            data_size: 100,
            symbol_size: 768,
            symbols_count: 5,
        };
        let result = FecEncoder::validate_fec_type(&fec_type);

        assert!(result.is_err());
        match result {
            Err(RldpError::UnsupportedFecType(msg)) => {
                assert!(msg.contains("Online"));
            }
            _ => panic!("Expected UnsupportedFecType error"),
        }
    }

    #[test]
    fn test_encode_decode_small() {
        let data = b"Hello, RLDP! This is a test message.";
        let encoder = FecEncoder::new(data);

        // Get all packets
        let packets = encoder.encode_all(5);

        // Create decoder
        let mut decoder = FecDecoder::new(data.len(), encoder.symbol_size());

        // Add packets until decoded
        for (_seqno, packet_data) in &packets {
            if decoder.add_packet(packet_data) {
                break;
            }
        }

        assert!(decoder.is_complete());
        let decoded = decoder.decode().unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_encode_decode_large() {
        // Test with larger data (multiple symbols)
        let data: Vec<u8> = (0..5000).map(|i| (i % 256) as u8).collect();
        let encoder = FecEncoder::new(&data);

        // Get all packets with extra repair symbols
        let packets = encoder.encode_all(10);

        // Create decoder
        let mut decoder = FecDecoder::new(data.len(), encoder.symbol_size());

        // Add packets until decoded
        for (_seqno, packet_data) in &packets {
            if decoder.add_packet(packet_data) {
                break;
            }
        }

        assert!(decoder.is_complete());
        let decoded = decoder.decode().unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_decode_with_loss() {
        // Test that we can decode even with some packet loss
        let data: Vec<u8> = (0..2000).map(|i| (i % 256) as u8).collect();
        let encoder = FecEncoder::new(&data);

        // Get packets with many extra repair symbols
        let packets = encoder.encode_all(30);

        // Create decoder
        let mut decoder = FecDecoder::new(data.len(), encoder.symbol_size());

        // Skip every other packet (50% loss)
        for (i, (_seqno, packet_data)) in packets.iter().enumerate() {
            if i % 2 == 0 {
                continue; // Skip this packet (simulating loss)
            }
            if decoder.add_packet(packet_data) {
                break;
            }
        }

        // If not complete, add more packets
        if !decoder.is_complete() {
            for (_seqno, packet_data) in &packets {
                if decoder.add_packet(packet_data) {
                    break;
                }
            }
        }

        assert!(
            decoder.is_complete(),
            "Failed to decode with {} packets received",
            decoder.packets_received()
        );
        let decoded = decoder.decode().unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_fec_type() {
        let data = b"Test data for FEC type";
        let encoder = FecEncoder::new(data);
        let fec_type = encoder.fec_type();

        assert_eq!(fec_type.data_size(), data.len() as i32);
        assert_eq!(fec_type.symbol_size(), SYMBOL_SIZE as i32);

        // Test decoder from fec_type
        let decoder = FecDecoder::from_fec_type(&fec_type).unwrap();
        assert_eq!(decoder.data_size(), data.len());
    }

    #[test]
    fn test_encode_for_transfer() {
        let data = b"Test data for RLDP transfer";
        let (fec_type, packets) = encode_for_transfer(data, 0.5);

        assert_eq!(fec_type.data_size(), data.len() as i32);
        assert!(!packets.is_empty());
    }

    #[test]
    fn test_decode_from_symbols() {
        let data = b"Test data for symbol decoding";
        let (fec_type, packets) = encode_for_transfer(data, 1.0);

        let decoded = decode_from_symbols(&fec_type, packets).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_packet_iterator() {
        let data = b"Iterator test data for FEC encoding";
        let encoder = FecEncoder::new(data);

        let packets: Vec<_> = encoder.packet_iter().take(10).collect();
        assert!(!packets.is_empty());

        // Verify sequence numbers are sequential
        for (i, (seqno, _)) in packets.iter().enumerate() {
            assert_eq!(*seqno, i as u32);
        }
    }

    #[test]
    fn test_empty_data() {
        let data = b"";
        let encoder = FecEncoder::new(data);

        assert_eq!(encoder.data_size(), 0);
        assert_eq!(encoder.symbols_count(), 0);

        let packets = encoder.encode_all(1);
        assert!(packets.is_empty());

        let decoder = FecDecoder::new(0, SYMBOL_SIZE);
        assert!(decoder.is_complete());
        let decoded = decoder.decode().unwrap();
        assert!(decoded.is_empty());
    }

    #[test]
    fn test_single_byte() {
        let data = b"X";
        let encoder = FecEncoder::new(data);
        let packets = encoder.encode_all(2);

        let mut decoder = FecDecoder::new(data.len(), encoder.symbol_size());
        for (_seqno, packet_data) in &packets {
            if decoder.add_packet(packet_data) {
                break;
            }
        }

        assert!(decoder.is_complete());
        let decoded = decoder.decode().unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_exact_symbol_size() {
        // Data exactly one symbol size
        let data: Vec<u8> = (0..SYMBOL_SIZE).map(|i| (i % 256) as u8).collect();
        let encoder = FecEncoder::new(&data);
        let packets = encoder.encode_all(3);

        let mut decoder = FecDecoder::new(data.len(), encoder.symbol_size());
        for (_seqno, packet_data) in &packets {
            if decoder.add_packet(packet_data) {
                break;
            }
        }

        assert!(decoder.is_complete());
        let decoded = decoder.decode().unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_repair_packet_generation() {
        let data = b"Test data for repair packet generation";
        let encoder = FecEncoder::new(data);

        // Generate individual repair packets
        let repair1 = encoder.encode_repair(0);
        let repair2 = encoder.encode_repair(1);

        assert!(repair1.is_some());
        assert!(repair2.is_some());
        assert_ne!(repair1, repair2);
    }
}
