//! TL structures for RLDP protocol.
//!
//! This module defines the TL (Type Language) structures used by RLDP
//! for reliable large datagram transfer over ADNL UDP.

use ton_adnl::{TlReader, TlWriter};

// ============================================================================
// TL Schema IDs (CRC32 of schema definitions)
// ============================================================================

/// fec.raptorQ data_size:int symbol_size:int symbols_count:int = fec.Type
pub const FEC_RAPTORQ: u32 = 0x19a4f8ba;

/// fec.roundRobin data_size:int symbol_size:int symbols_count:int = fec.Type
pub const FEC_ROUND_ROBIN: u32 = 0x32f528d5;

/// fec.online data_size:int symbol_size:int symbols_count:int = fec.Type
pub const FEC_ONLINE: u32 = 0xe7c59bba;

/// rldp.messagePart transfer_id:int256 fec_type:fec.Type part:int total_size:long seqno:int data:bytes = rldp.MessagePart
pub const RLDP_MESSAGE_PART: u32 = 0x7d1f3f2f;

/// rldp.confirm transfer_id:int256 part:int seqno:int = rldp.Confirm
pub const RLDP_CONFIRM: u32 = 0x825da4c6;

/// rldp.complete transfer_id:int256 part:int = rldp.Complete
pub const RLDP_COMPLETE: u32 = 0xb71a7818;

/// rldp.query query_id:int256 max_answer_size:long timeout:int data:bytes = rldp.Query
pub const RLDP_QUERY: u32 = 0x3b5d0d8f;

/// rldp.answer query_id:int256 data:bytes = rldp.Answer
pub const RLDP_ANSWER: u32 = 0xa556c3cc;

// ============================================================================
// FEC Types
// ============================================================================

/// FEC (Forward Error Correction) type configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FecType {
    /// RaptorQ FEC - most commonly used in TON.
    RaptorQ {
        data_size: i32,
        symbol_size: i32,
        symbols_count: i32,
    },
    /// Round-robin FEC.
    RoundRobin {
        data_size: i32,
        symbol_size: i32,
        symbols_count: i32,
    },
    /// Online FEC.
    Online {
        data_size: i32,
        symbol_size: i32,
        symbols_count: i32,
    },
}

impl FecType {
    /// Creates a new RaptorQ FEC type with the given parameters.
    pub fn raptorq(data_size: i32, symbol_size: i32, symbols_count: i32) -> Self {
        Self::RaptorQ {
            data_size,
            symbol_size,
            symbols_count,
        }
    }

    /// Returns the data size.
    pub fn data_size(&self) -> i32 {
        match self {
            FecType::RaptorQ { data_size, .. } => *data_size,
            FecType::RoundRobin { data_size, .. } => *data_size,
            FecType::Online { data_size, .. } => *data_size,
        }
    }

    /// Returns the symbol size.
    pub fn symbol_size(&self) -> i32 {
        match self {
            FecType::RaptorQ { symbol_size, .. } => *symbol_size,
            FecType::RoundRobin { symbol_size, .. } => *symbol_size,
            FecType::Online { symbol_size, .. } => *symbol_size,
        }
    }

    /// Returns the symbols count.
    pub fn symbols_count(&self) -> i32 {
        match self {
            FecType::RaptorQ { symbols_count, .. } => *symbols_count,
            FecType::RoundRobin { symbols_count, .. } => *symbols_count,
            FecType::Online { symbols_count, .. } => *symbols_count,
        }
    }

    /// Returns the TL schema ID for this FEC type.
    pub fn schema_id(&self) -> u32 {
        match self {
            FecType::RaptorQ { .. } => FEC_RAPTORQ,
            FecType::RoundRobin { .. } => FEC_ROUND_ROBIN,
            FecType::Online { .. } => FEC_ONLINE,
        }
    }

    /// Serializes the FEC type to TL format.
    pub fn write_to(&self, writer: &mut TlWriter) {
        writer.write_u32(self.schema_id());
        writer.write_i32(self.data_size());
        writer.write_i32(self.symbol_size());
        writer.write_i32(self.symbols_count());
    }

    /// Deserializes a FEC type from TL format.
    pub fn read_from(reader: &mut TlReader) -> Result<Self, RldpTypeError> {
        let schema_id = reader.read_u32().map_err(|e| RldpTypeError::TlReadError(e.to_string()))?;
        let data_size = reader.read_i32().map_err(|e| RldpTypeError::TlReadError(e.to_string()))?;
        let symbol_size = reader.read_i32().map_err(|e| RldpTypeError::TlReadError(e.to_string()))?;
        let symbols_count = reader.read_i32().map_err(|e| RldpTypeError::TlReadError(e.to_string()))?;

        match schema_id {
            FEC_RAPTORQ => Ok(FecType::RaptorQ {
                data_size,
                symbol_size,
                symbols_count,
            }),
            FEC_ROUND_ROBIN => Ok(FecType::RoundRobin {
                data_size,
                symbol_size,
                symbols_count,
            }),
            FEC_ONLINE => Ok(FecType::Online {
                data_size,
                symbol_size,
                symbols_count,
            }),
            _ => Err(RldpTypeError::UnknownFecType(schema_id)),
        }
    }
}

// ============================================================================
// RLDP Message Types
// ============================================================================

/// RLDP message part - carries FEC-encoded data chunks.
#[derive(Debug, Clone)]
pub struct RldpMessagePart {
    /// Transfer identifier (random 256-bit value).
    pub transfer_id: [u8; 32],
    /// FEC type configuration.
    pub fec_type: FecType,
    /// Part number (for multi-part transfers).
    pub part: i32,
    /// Total size of the original data.
    pub total_size: i64,
    /// Sequence number of this symbol.
    pub seqno: i32,
    /// FEC-encoded symbol data.
    pub data: Vec<u8>,
}

impl RldpMessagePart {
    /// Creates a new RLDP message part.
    pub fn new(
        transfer_id: [u8; 32],
        fec_type: FecType,
        part: i32,
        total_size: i64,
        seqno: i32,
        data: Vec<u8>,
    ) -> Self {
        Self {
            transfer_id,
            fec_type,
            part,
            total_size,
            seqno,
            data,
        }
    }

    /// Serializes the message part to TL format.
    pub fn write_to(&self, writer: &mut TlWriter) {
        writer.write_u32(RLDP_MESSAGE_PART);
        writer.write_int256(&self.transfer_id);
        self.fec_type.write_to(writer);
        writer.write_i32(self.part);
        writer.write_i64(self.total_size);
        writer.write_i32(self.seqno);
        writer.write_bytes(&self.data);
    }

    /// Serializes to a byte vector.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut writer = TlWriter::new();
        self.write_to(&mut writer);
        writer.finish()
    }

    /// Deserializes from TL format.
    pub fn read_from(reader: &mut TlReader) -> Result<Self, RldpTypeError> {
        let schema_id = reader.read_u32().map_err(|e| RldpTypeError::TlReadError(e.to_string()))?;
        if schema_id != RLDP_MESSAGE_PART {
            return Err(RldpTypeError::UnexpectedSchemaId {
                expected: RLDP_MESSAGE_PART,
                got: schema_id,
            });
        }

        let transfer_id = reader.read_int256().map_err(|e| RldpTypeError::TlReadError(e.to_string()))?;
        let fec_type = FecType::read_from(reader)?;
        let part = reader.read_i32().map_err(|e| RldpTypeError::TlReadError(e.to_string()))?;
        let total_size = reader.read_i64().map_err(|e| RldpTypeError::TlReadError(e.to_string()))?;
        let seqno = reader.read_i32().map_err(|e| RldpTypeError::TlReadError(e.to_string()))?;
        let data = reader.read_bytes().map_err(|e| RldpTypeError::TlReadError(e.to_string()))?;

        Ok(Self {
            transfer_id,
            fec_type,
            part,
            total_size,
            seqno,
            data,
        })
    }
}

/// RLDP confirm - acknowledges received symbols.
#[derive(Debug, Clone, Copy)]
pub struct RldpConfirm {
    /// Transfer identifier.
    pub transfer_id: [u8; 32],
    /// Part number.
    pub part: i32,
    /// Last received sequence number.
    pub seqno: i32,
}

impl RldpConfirm {
    /// Creates a new RLDP confirm message.
    pub fn new(transfer_id: [u8; 32], part: i32, seqno: i32) -> Self {
        Self {
            transfer_id,
            part,
            seqno,
        }
    }

    /// Serializes the confirm message to TL format.
    pub fn write_to(&self, writer: &mut TlWriter) {
        writer.write_u32(RLDP_CONFIRM);
        writer.write_int256(&self.transfer_id);
        writer.write_i32(self.part);
        writer.write_i32(self.seqno);
    }

    /// Serializes to a byte vector.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut writer = TlWriter::new();
        self.write_to(&mut writer);
        writer.finish()
    }

    /// Deserializes from TL format.
    pub fn read_from(reader: &mut TlReader) -> Result<Self, RldpTypeError> {
        let schema_id = reader.read_u32().map_err(|e| RldpTypeError::TlReadError(e.to_string()))?;
        if schema_id != RLDP_CONFIRM {
            return Err(RldpTypeError::UnexpectedSchemaId {
                expected: RLDP_CONFIRM,
                got: schema_id,
            });
        }

        let transfer_id = reader.read_int256().map_err(|e| RldpTypeError::TlReadError(e.to_string()))?;
        let part = reader.read_i32().map_err(|e| RldpTypeError::TlReadError(e.to_string()))?;
        let seqno = reader.read_i32().map_err(|e| RldpTypeError::TlReadError(e.to_string()))?;

        Ok(Self {
            transfer_id,
            part,
            seqno,
        })
    }
}

/// RLDP complete - signals transfer completion.
#[derive(Debug, Clone, Copy)]
pub struct RldpComplete {
    /// Transfer identifier.
    pub transfer_id: [u8; 32],
    /// Part number.
    pub part: i32,
}

impl RldpComplete {
    /// Creates a new RLDP complete message.
    pub fn new(transfer_id: [u8; 32], part: i32) -> Self {
        Self { transfer_id, part }
    }

    /// Serializes the complete message to TL format.
    pub fn write_to(&self, writer: &mut TlWriter) {
        writer.write_u32(RLDP_COMPLETE);
        writer.write_int256(&self.transfer_id);
        writer.write_i32(self.part);
    }

    /// Serializes to a byte vector.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut writer = TlWriter::new();
        self.write_to(&mut writer);
        writer.finish()
    }

    /// Deserializes from TL format.
    pub fn read_from(reader: &mut TlReader) -> Result<Self, RldpTypeError> {
        let schema_id = reader.read_u32().map_err(|e| RldpTypeError::TlReadError(e.to_string()))?;
        if schema_id != RLDP_COMPLETE {
            return Err(RldpTypeError::UnexpectedSchemaId {
                expected: RLDP_COMPLETE,
                got: schema_id,
            });
        }

        let transfer_id = reader.read_int256().map_err(|e| RldpTypeError::TlReadError(e.to_string()))?;
        let part = reader.read_i32().map_err(|e| RldpTypeError::TlReadError(e.to_string()))?;

        Ok(Self { transfer_id, part })
    }
}

/// RLDP query - request with expected response.
#[derive(Debug, Clone)]
pub struct RldpQuery {
    /// Query identifier.
    pub query_id: [u8; 32],
    /// Maximum expected answer size in bytes.
    pub max_answer_size: i64,
    /// Timeout in milliseconds.
    pub timeout: i32,
    /// Query data.
    pub data: Vec<u8>,
}

impl RldpQuery {
    /// Creates a new RLDP query.
    pub fn new(query_id: [u8; 32], max_answer_size: i64, timeout: i32, data: Vec<u8>) -> Self {
        Self {
            query_id,
            max_answer_size,
            timeout,
            data,
        }
    }

    /// Serializes the query to TL format.
    pub fn write_to(&self, writer: &mut TlWriter) {
        writer.write_u32(RLDP_QUERY);
        writer.write_int256(&self.query_id);
        writer.write_i64(self.max_answer_size);
        writer.write_i32(self.timeout);
        writer.write_bytes(&self.data);
    }

    /// Serializes to a byte vector.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut writer = TlWriter::new();
        self.write_to(&mut writer);
        writer.finish()
    }

    /// Deserializes from TL format.
    pub fn read_from(reader: &mut TlReader) -> Result<Self, RldpTypeError> {
        let schema_id = reader.read_u32().map_err(|e| RldpTypeError::TlReadError(e.to_string()))?;
        if schema_id != RLDP_QUERY {
            return Err(RldpTypeError::UnexpectedSchemaId {
                expected: RLDP_QUERY,
                got: schema_id,
            });
        }

        let query_id = reader.read_int256().map_err(|e| RldpTypeError::TlReadError(e.to_string()))?;
        let max_answer_size = reader.read_i64().map_err(|e| RldpTypeError::TlReadError(e.to_string()))?;
        let timeout = reader.read_i32().map_err(|e| RldpTypeError::TlReadError(e.to_string()))?;
        let data = reader.read_bytes().map_err(|e| RldpTypeError::TlReadError(e.to_string()))?;

        Ok(Self {
            query_id,
            max_answer_size,
            timeout,
            data,
        })
    }
}

/// RLDP answer - response to a query.
#[derive(Debug, Clone)]
pub struct RldpAnswer {
    /// Query identifier this answers.
    pub query_id: [u8; 32],
    /// Answer data.
    pub data: Vec<u8>,
}

impl RldpAnswer {
    /// Creates a new RLDP answer.
    pub fn new(query_id: [u8; 32], data: Vec<u8>) -> Self {
        Self { query_id, data }
    }

    /// Serializes the answer to TL format.
    pub fn write_to(&self, writer: &mut TlWriter) {
        writer.write_u32(RLDP_ANSWER);
        writer.write_int256(&self.query_id);
        writer.write_bytes(&self.data);
    }

    /// Serializes to a byte vector.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut writer = TlWriter::new();
        self.write_to(&mut writer);
        writer.finish()
    }

    /// Deserializes from TL format.
    pub fn read_from(reader: &mut TlReader) -> Result<Self, RldpTypeError> {
        let schema_id = reader.read_u32().map_err(|e| RldpTypeError::TlReadError(e.to_string()))?;
        if schema_id != RLDP_ANSWER {
            return Err(RldpTypeError::UnexpectedSchemaId {
                expected: RLDP_ANSWER,
                got: schema_id,
            });
        }

        let query_id = reader.read_int256().map_err(|e| RldpTypeError::TlReadError(e.to_string()))?;
        let data = reader.read_bytes().map_err(|e| RldpTypeError::TlReadError(e.to_string()))?;

        Ok(Self { query_id, data })
    }
}

// ============================================================================
// RLDP Message Enum
// ============================================================================

/// Any RLDP message.
#[derive(Debug, Clone)]
pub enum RldpMessage {
    MessagePart(RldpMessagePart),
    Confirm(RldpConfirm),
    Complete(RldpComplete),
    Query(RldpQuery),
    Answer(RldpAnswer),
}

impl RldpMessage {
    /// Returns the schema ID for this message type.
    pub fn schema_id(&self) -> u32 {
        match self {
            RldpMessage::MessagePart(_) => RLDP_MESSAGE_PART,
            RldpMessage::Confirm(_) => RLDP_CONFIRM,
            RldpMessage::Complete(_) => RLDP_COMPLETE,
            RldpMessage::Query(_) => RLDP_QUERY,
            RldpMessage::Answer(_) => RLDP_ANSWER,
        }
    }

    /// Serializes the message to TL format.
    pub fn write_to(&self, writer: &mut TlWriter) {
        match self {
            RldpMessage::MessagePart(m) => m.write_to(writer),
            RldpMessage::Confirm(m) => m.write_to(writer),
            RldpMessage::Complete(m) => m.write_to(writer),
            RldpMessage::Query(m) => m.write_to(writer),
            RldpMessage::Answer(m) => m.write_to(writer),
        }
    }

    /// Serializes to a byte vector.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut writer = TlWriter::new();
        self.write_to(&mut writer);
        writer.finish()
    }

    /// Deserializes from TL format.
    pub fn read_from(reader: &mut TlReader) -> Result<Self, RldpTypeError> {
        let schema_id = reader.peek_u32().map_err(|e| RldpTypeError::TlReadError(e.to_string()))?;

        match schema_id {
            RLDP_MESSAGE_PART => Ok(RldpMessage::MessagePart(RldpMessagePart::read_from(reader)?)),
            RLDP_CONFIRM => Ok(RldpMessage::Confirm(RldpConfirm::read_from(reader)?)),
            RLDP_COMPLETE => Ok(RldpMessage::Complete(RldpComplete::read_from(reader)?)),
            RLDP_QUERY => Ok(RldpMessage::Query(RldpQuery::read_from(reader)?)),
            RLDP_ANSWER => Ok(RldpMessage::Answer(RldpAnswer::read_from(reader)?)),
            _ => Err(RldpTypeError::UnknownMessageType(schema_id)),
        }
    }

    /// Parses from bytes.
    pub fn from_bytes(data: &[u8]) -> Result<Self, RldpTypeError> {
        let mut reader = TlReader::new(data);
        Self::read_from(&mut reader)
    }
}

// ============================================================================
// Error Type
// ============================================================================

/// Errors that can occur when working with RLDP types.
#[derive(Debug, Clone, thiserror::Error)]
pub enum RldpTypeError {
    #[error("TL read error: {0}")]
    TlReadError(String),

    #[error("Unknown FEC type: 0x{0:08x}")]
    UnknownFecType(u32),

    #[error("Unknown message type: 0x{0:08x}")]
    UnknownMessageType(u32),

    #[error("Unexpected schema ID: expected 0x{expected:08x}, got 0x{got:08x}")]
    UnexpectedSchemaId { expected: u32, got: u32 },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fec_type_raptorq() {
        let fec = FecType::raptorq(1024, 768, 2);
        assert_eq!(fec.data_size(), 1024);
        assert_eq!(fec.symbol_size(), 768);
        assert_eq!(fec.symbols_count(), 2);
        assert_eq!(fec.schema_id(), FEC_RAPTORQ);
    }

    #[test]
    fn test_fec_type_roundtrip() {
        let original = FecType::RaptorQ {
            data_size: 1024,
            symbol_size: 768,
            symbols_count: 2,
        };

        let mut writer = TlWriter::new();
        original.write_to(&mut writer);
        let bytes = writer.finish();

        let mut reader = TlReader::new(&bytes);
        let parsed = FecType::read_from(&mut reader).unwrap();

        assert_eq!(original, parsed);
    }

    #[test]
    fn test_message_part_roundtrip() {
        let transfer_id = [42u8; 32];
        let fec_type = FecType::raptorq(1024, 768, 2);
        let original = RldpMessagePart::new(
            transfer_id,
            fec_type,
            0,
            1024,
            5,
            vec![1, 2, 3, 4, 5],
        );

        let bytes = original.to_bytes();
        let mut reader = TlReader::new(&bytes);
        let parsed = RldpMessagePart::read_from(&mut reader).unwrap();

        assert_eq!(original.transfer_id, parsed.transfer_id);
        assert_eq!(original.fec_type, parsed.fec_type);
        assert_eq!(original.part, parsed.part);
        assert_eq!(original.total_size, parsed.total_size);
        assert_eq!(original.seqno, parsed.seqno);
        assert_eq!(original.data, parsed.data);
    }

    #[test]
    fn test_confirm_roundtrip() {
        let original = RldpConfirm::new([1u8; 32], 0, 10);

        let bytes = original.to_bytes();
        let mut reader = TlReader::new(&bytes);
        let parsed = RldpConfirm::read_from(&mut reader).unwrap();

        assert_eq!(original.transfer_id, parsed.transfer_id);
        assert_eq!(original.part, parsed.part);
        assert_eq!(original.seqno, parsed.seqno);
    }

    #[test]
    fn test_complete_roundtrip() {
        let original = RldpComplete::new([2u8; 32], 0);

        let bytes = original.to_bytes();
        let mut reader = TlReader::new(&bytes);
        let parsed = RldpComplete::read_from(&mut reader).unwrap();

        assert_eq!(original.transfer_id, parsed.transfer_id);
        assert_eq!(original.part, parsed.part);
    }

    #[test]
    fn test_query_roundtrip() {
        let original = RldpQuery::new(
            [3u8; 32],
            1024 * 1024,
            30000,
            b"test query data".to_vec(),
        );

        let bytes = original.to_bytes();
        let mut reader = TlReader::new(&bytes);
        let parsed = RldpQuery::read_from(&mut reader).unwrap();

        assert_eq!(original.query_id, parsed.query_id);
        assert_eq!(original.max_answer_size, parsed.max_answer_size);
        assert_eq!(original.timeout, parsed.timeout);
        assert_eq!(original.data, parsed.data);
    }

    #[test]
    fn test_answer_roundtrip() {
        let original = RldpAnswer::new([4u8; 32], b"test answer data".to_vec());

        let bytes = original.to_bytes();
        let mut reader = TlReader::new(&bytes);
        let parsed = RldpAnswer::read_from(&mut reader).unwrap();

        assert_eq!(original.query_id, parsed.query_id);
        assert_eq!(original.data, parsed.data);
    }

    #[test]
    fn test_rldp_message_enum() {
        let messages: Vec<RldpMessage> = vec![
            RldpMessage::Confirm(RldpConfirm::new([1u8; 32], 0, 5)),
            RldpMessage::Complete(RldpComplete::new([2u8; 32], 0)),
            RldpMessage::Query(RldpQuery::new([3u8; 32], 1024, 1000, vec![1, 2, 3])),
            RldpMessage::Answer(RldpAnswer::new([4u8; 32], vec![4, 5, 6])),
        ];

        for original in messages {
            let bytes = original.to_bytes();
            let parsed = RldpMessage::from_bytes(&bytes).unwrap();
            assert_eq!(original.schema_id(), parsed.schema_id());
        }
    }
}
