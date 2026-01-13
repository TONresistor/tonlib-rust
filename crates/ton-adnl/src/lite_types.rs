//! Data types for the LiteServer protocol.
//!
//! This module defines the structures used for liteserver queries and responses,
//! including block identifiers, account states, and TVM stack entries.

use std::fmt;
use std::sync::Arc;
use ton_cell::Cell;
use ton_tl::{TlReader, TlWriter, TlResult};

// ============================================================================
// Block Identifiers
// ============================================================================

/// Block identifier without hashes.
///
/// Used for block lookups where the exact hashes are not yet known.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct BlockId {
    /// Workchain ID (-1 for masterchain, 0 for basechain).
    pub workchain: i32,
    /// Shard identifier.
    pub shard: i64,
    /// Block sequence number.
    pub seqno: u32,
}

impl BlockId {
    /// Creates a new block ID.
    pub fn new(workchain: i32, shard: i64, seqno: u32) -> Self {
        Self { workchain, shard, seqno }
    }

    /// Creates a block ID for the masterchain.
    pub fn masterchain(seqno: u32) -> Self {
        Self {
            workchain: -1,
            shard: i64::MIN, // 0x8000000000000000
            seqno,
        }
    }

    /// Serializes the block ID to TL format.
    pub fn serialize(&self, writer: &mut TlWriter) {
        writer.write_i32(self.workchain);
        writer.write_i64(self.shard);
        writer.write_u32(self.seqno);
    }

    /// Deserializes a block ID from TL format.
    pub fn deserialize(reader: &mut TlReader) -> TlResult<Self> {
        Ok(Self {
            workchain: reader.read_i32()?,
            shard: reader.read_i64()?,
            seqno: reader.read_u32()?,
        })
    }
}

impl fmt::Display for BlockId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "({}:{:016x}:{})", self.workchain, self.shard as u64, self.seqno)
    }
}

/// Extended block identifier with hashes.
///
/// This is the full block reference used in most liteserver operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct BlockIdExt {
    /// Workchain ID (-1 for masterchain, 0 for basechain).
    pub workchain: i32,
    /// Shard identifier.
    pub shard: i64,
    /// Block sequence number.
    pub seqno: u32,
    /// Root hash of the block.
    pub root_hash: [u8; 32],
    /// File hash of the block.
    pub file_hash: [u8; 32],
}

impl BlockIdExt {
    /// Creates a new extended block ID.
    pub fn new(
        workchain: i32,
        shard: i64,
        seqno: u32,
        root_hash: [u8; 32],
        file_hash: [u8; 32],
    ) -> Self {
        Self {
            workchain,
            shard,
            seqno,
            root_hash,
            file_hash,
        }
    }

    /// Returns the basic block ID without hashes.
    pub fn to_block_id(&self) -> BlockId {
        BlockId {
            workchain: self.workchain,
            shard: self.shard,
            seqno: self.seqno,
        }
    }

    /// Checks if this is a masterchain block.
    pub fn is_masterchain(&self) -> bool {
        self.workchain == -1
    }

    /// Serializes the block ID to TL format.
    pub fn serialize(&self, writer: &mut TlWriter) {
        writer.write_i32(self.workchain);
        writer.write_i64(self.shard);
        writer.write_u32(self.seqno);
        writer.write_u256(&self.root_hash);
        writer.write_u256(&self.file_hash);
    }

    /// Deserializes a block ID from TL format.
    pub fn deserialize(reader: &mut TlReader) -> TlResult<Self> {
        Ok(Self {
            workchain: reader.read_i32()?,
            shard: reader.read_i64()?,
            seqno: reader.read_u32()?,
            root_hash: reader.read_u256()?,
            file_hash: reader.read_u256()?,
        })
    }
}

impl fmt::Display for BlockIdExt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "({}:{:016x}:{}:{}:{})",
            self.workchain,
            self.shard as u64,
            self.seqno,
            hex::encode(&self.root_hash[..8]),
            hex::encode(&self.file_hash[..8])
        )
    }
}

/// Zero state identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ZeroStateIdExt {
    /// Workchain ID.
    pub workchain: i32,
    /// Root hash of the zero state.
    pub root_hash: [u8; 32],
    /// File hash of the zero state.
    pub file_hash: [u8; 32],
}

impl ZeroStateIdExt {
    /// Serializes the zero state ID to TL format.
    pub fn serialize(&self, writer: &mut TlWriter) {
        writer.write_i32(self.workchain);
        writer.write_u256(&self.root_hash);
        writer.write_u256(&self.file_hash);
    }

    /// Deserializes a zero state ID from TL format.
    pub fn deserialize(reader: &mut TlReader) -> TlResult<Self> {
        Ok(Self {
            workchain: reader.read_i32()?,
            root_hash: reader.read_u256()?,
            file_hash: reader.read_u256()?,
        })
    }
}

// ============================================================================
// Account Types
// ============================================================================

/// Account address (workchain + 256-bit address).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AccountAddress {
    /// Workchain ID (0 for basechain, -1 for masterchain).
    pub workchain: i32,
    /// 256-bit account address.
    pub address: [u8; 32],
}

impl AccountAddress {
    /// Creates a new account address.
    pub fn new(workchain: i32, address: [u8; 32]) -> Self {
        Self { workchain, address }
    }

    /// Parses an address from a raw string format "workchain:hex_address".
    pub fn from_raw_string(s: &str) -> Result<Self, &'static str> {
        let parts: Vec<&str> = s.split(':').collect();
        if parts.len() != 2 {
            return Err("Invalid address format, expected 'workchain:hex_address'");
        }

        let workchain: i32 = parts[0].parse().map_err(|_| "Invalid workchain")?;
        let hex_addr = parts[1];

        if hex_addr.len() != 64 {
            return Err("Address must be 64 hex characters");
        }

        let mut address = [0u8; 32];
        hex::decode_to_slice(hex_addr, &mut address)
            .map_err(|_| "Invalid hex address")?;

        Ok(Self { workchain, address })
    }

    /// Returns the address in raw string format "workchain:hex_address".
    pub fn to_raw_string(&self) -> String {
        format!("{}:{}", self.workchain, hex::encode(self.address))
    }

    /// Serializes the account address to TL format (liteServer.accountId).
    pub fn serialize(&self, writer: &mut TlWriter) {
        writer.write_i32(self.workchain);
        writer.write_u256(&self.address);
    }

    /// Deserializes an account address from TL format.
    pub fn deserialize(reader: &mut TlReader) -> TlResult<Self> {
        Ok(Self {
            workchain: reader.read_i32()?,
            address: reader.read_u256()?,
        })
    }
}

impl fmt::Display for AccountAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.workchain, hex::encode(self.address))
    }
}

// ============================================================================
// Response Types
// ============================================================================

/// Masterchain info response.
#[derive(Debug, Clone)]
pub struct MasterchainInfo {
    /// Last known masterchain block.
    pub last: BlockIdExt,
    /// State root hash.
    pub state_root_hash: [u8; 32],
    /// Initial (zero) state.
    pub init: ZeroStateIdExt,
}

impl MasterchainInfo {
    /// Deserializes from TL format (expects constructor ID already read).
    pub fn deserialize(reader: &mut TlReader) -> TlResult<Self> {
        Ok(Self {
            last: BlockIdExt::deserialize(reader)?,
            state_root_hash: reader.read_u256()?,
            init: ZeroStateIdExt::deserialize(reader)?,
        })
    }
}

/// Extended masterchain info response.
#[derive(Debug, Clone)]
pub struct MasterchainInfoExt {
    /// Mode flags.
    pub mode: u32,
    /// Liteserver version.
    pub version: i32,
    /// Liteserver capabilities.
    pub capabilities: i64,
    /// Last known masterchain block.
    pub last: BlockIdExt,
    /// Last block Unix time.
    pub last_utime: u32,
    /// Current Unix time.
    pub now: u32,
    /// State root hash.
    pub state_root_hash: [u8; 32],
    /// Initial (zero) state.
    pub init: ZeroStateIdExt,
}

impl MasterchainInfoExt {
    /// Deserializes from TL format.
    pub fn deserialize(reader: &mut TlReader) -> TlResult<Self> {
        Ok(Self {
            mode: reader.read_u32()?,
            version: reader.read_i32()?,
            capabilities: reader.read_i64()?,
            last: BlockIdExt::deserialize(reader)?,
            last_utime: reader.read_u32()?,
            now: reader.read_u32()?,
            state_root_hash: reader.read_u256()?,
            init: ZeroStateIdExt::deserialize(reader)?,
        })
    }
}

/// Liteserver version response.
#[derive(Debug, Clone)]
pub struct LiteServerVersion {
    /// Mode flags.
    pub mode: u32,
    /// Version number.
    pub version: i32,
    /// Capabilities bitmask.
    pub capabilities: i64,
    /// Current Unix time.
    pub now: u32,
}

impl LiteServerVersion {
    /// Deserializes from TL format.
    pub fn deserialize(reader: &mut TlReader) -> TlResult<Self> {
        Ok(Self {
            mode: reader.read_u32()?,
            version: reader.read_i32()?,
            capabilities: reader.read_i64()?,
            now: reader.read_u32()?,
        })
    }
}

/// Block data response.
#[derive(Debug, Clone)]
pub struct BlockData {
    /// Block identifier.
    pub id: BlockIdExt,
    /// Block data as BoC.
    pub data: Vec<u8>,
}

impl BlockData {
    /// Deserializes from TL format.
    pub fn deserialize(reader: &mut TlReader) -> TlResult<Self> {
        Ok(Self {
            id: BlockIdExt::deserialize(reader)?,
            data: reader.read_bytes()?,
        })
    }
}

/// Block header response.
#[derive(Debug, Clone)]
pub struct BlockHeader {
    /// Block identifier.
    pub id: BlockIdExt,
    /// Mode flags.
    pub mode: u32,
    /// Header proof as BoC.
    pub header_proof: Vec<u8>,
}

impl BlockHeader {
    /// Deserializes from TL format.
    pub fn deserialize(reader: &mut TlReader) -> TlResult<Self> {
        Ok(Self {
            id: BlockIdExt::deserialize(reader)?,
            mode: reader.read_u32()?,
            header_proof: reader.read_bytes()?,
        })
    }
}

/// Account state response.
#[derive(Debug, Clone)]
pub struct AccountState {
    /// Block at which state was queried.
    pub block_id: BlockIdExt,
    /// Shard block containing the account.
    pub shard_block: BlockIdExt,
    /// Proof for shard block (BoC).
    pub shard_proof: Vec<u8>,
    /// Proof for account state (BoC).
    pub proof: Vec<u8>,
    /// Account state (BoC).
    pub state: Vec<u8>,
}

impl AccountState {
    /// Deserializes from TL format.
    pub fn deserialize(reader: &mut TlReader) -> TlResult<Self> {
        Ok(Self {
            block_id: BlockIdExt::deserialize(reader)?,
            shard_block: BlockIdExt::deserialize(reader)?,
            shard_proof: reader.read_bytes()?,
            proof: reader.read_bytes()?,
            state: reader.read_bytes()?,
        })
    }

    /// Returns true if the account exists.
    pub fn exists(&self) -> bool {
        !self.state.is_empty()
    }
}

/// Run method (get method) result.
#[derive(Debug, Clone)]
pub struct RunMethodResult {
    /// Mode flags.
    pub mode: u32,
    /// Block at which the method was executed.
    pub block_id: BlockIdExt,
    /// Shard block.
    pub shard_block: BlockIdExt,
    /// Shard proof (if mode & 1).
    pub shard_proof: Option<Vec<u8>>,
    /// Account proof (if mode & 1).
    pub proof: Option<Vec<u8>>,
    /// State proof (if mode & 2).
    pub state_proof: Option<Vec<u8>>,
    /// Initial c7 register (if mode & 8).
    pub init_c7: Option<Vec<u8>>,
    /// Library extras (if mode & 16).
    pub lib_extras: Option<Vec<u8>>,
    /// Exit code from TVM.
    pub exit_code: i32,
    /// Result stack (if mode & 4).
    pub result: Option<Vec<u8>>,
}

impl RunMethodResult {
    /// Deserializes from TL format.
    pub fn deserialize(reader: &mut TlReader) -> TlResult<Self> {
        let mode = reader.read_u32()?;
        let block_id = BlockIdExt::deserialize(reader)?;
        let shard_block = BlockIdExt::deserialize(reader)?;

        let shard_proof = if mode & 1 != 0 {
            Some(reader.read_bytes()?)
        } else {
            None
        };

        let proof = if mode & 1 != 0 {
            Some(reader.read_bytes()?)
        } else {
            None
        };

        let state_proof = if mode & 2 != 0 {
            Some(reader.read_bytes()?)
        } else {
            None
        };

        let init_c7 = if mode & 8 != 0 {
            Some(reader.read_bytes()?)
        } else {
            None
        };

        let lib_extras = if mode & 16 != 0 {
            Some(reader.read_bytes()?)
        } else {
            None
        };

        let exit_code = reader.read_i32()?;

        let result = if mode & 4 != 0 {
            Some(reader.read_bytes()?)
        } else {
            None
        };

        Ok(Self {
            mode,
            block_id,
            shard_block,
            shard_proof,
            proof,
            state_proof,
            init_c7,
            lib_extras,
            exit_code,
            result,
        })
    }

    /// Returns true if the method executed successfully.
    pub fn is_success(&self) -> bool {
        self.exit_code == 0
    }
}

/// All shards info response.
#[derive(Debug, Clone)]
pub struct AllShardsInfo {
    /// Block at which shards were queried.
    pub block_id: BlockIdExt,
    /// Proof as BoC.
    pub proof: Vec<u8>,
    /// Shards data as BoC.
    pub data: Vec<u8>,
}

impl AllShardsInfo {
    /// Deserializes from TL format.
    pub fn deserialize(reader: &mut TlReader) -> TlResult<Self> {
        Ok(Self {
            block_id: BlockIdExt::deserialize(reader)?,
            proof: reader.read_bytes()?,
            data: reader.read_bytes()?,
        })
    }
}

/// Shard info response.
#[derive(Debug, Clone)]
pub struct ShardInfo {
    /// Master block at which shard was queried.
    pub block_id: BlockIdExt,
    /// Shard block.
    pub shard_block: BlockIdExt,
    /// Shard proof as BoC.
    pub shard_proof: Vec<u8>,
    /// Shard descriptor as BoC.
    pub shard_descr: Vec<u8>,
}

impl ShardInfo {
    /// Deserializes from TL format.
    pub fn deserialize(reader: &mut TlReader) -> TlResult<Self> {
        Ok(Self {
            block_id: BlockIdExt::deserialize(reader)?,
            shard_block: BlockIdExt::deserialize(reader)?,
            shard_proof: reader.read_bytes()?,
            shard_descr: reader.read_bytes()?,
        })
    }
}

/// Transaction ID for listing transactions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransactionId {
    /// Mode flags indicating which fields are present.
    pub mode: u32,
    /// Account address (if mode & 1).
    pub account: Option<[u8; 32]>,
    /// Logical time (if mode & 2).
    pub lt: Option<u64>,
    /// Transaction hash (if mode & 4).
    pub hash: Option<[u8; 32]>,
}

impl TransactionId {
    /// Deserializes from TL format.
    pub fn deserialize(reader: &mut TlReader) -> TlResult<Self> {
        let mode = reader.read_u32()?;

        let account = if mode & 1 != 0 {
            Some(reader.read_u256()?)
        } else {
            None
        };

        let lt = if mode & 2 != 0 {
            Some(reader.read_u64()?)
        } else {
            None
        };

        let hash = if mode & 4 != 0 {
            Some(reader.read_u256()?)
        } else {
            None
        };

        Ok(Self { mode, account, lt, hash })
    }
}

/// Transaction ID v3 (for pagination).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransactionId3 {
    /// Account address.
    pub account: [u8; 32],
    /// Logical time.
    pub lt: u64,
}

impl TransactionId3 {
    /// Serializes to TL format.
    pub fn serialize(&self, writer: &mut TlWriter) {
        writer.write_u256(&self.account);
        writer.write_u64(self.lt);
    }

    /// Deserializes from TL format.
    pub fn deserialize(reader: &mut TlReader) -> TlResult<Self> {
        Ok(Self {
            account: reader.read_u256()?,
            lt: reader.read_u64()?,
        })
    }
}

/// Transaction info response.
#[derive(Debug, Clone)]
pub struct TransactionInfo {
    /// Block containing the transaction.
    pub block_id: BlockIdExt,
    /// Proof as BoC.
    pub proof: Vec<u8>,
    /// Transaction data as BoC.
    pub transaction: Vec<u8>,
}

impl TransactionInfo {
    /// Deserializes from TL format.
    pub fn deserialize(reader: &mut TlReader) -> TlResult<Self> {
        Ok(Self {
            block_id: BlockIdExt::deserialize(reader)?,
            proof: reader.read_bytes()?,
            transaction: reader.read_bytes()?,
        })
    }
}

/// Transaction list response.
#[derive(Debug, Clone)]
pub struct TransactionList {
    /// Block IDs for each transaction.
    pub ids: Vec<BlockIdExt>,
    /// Transactions data as BoC.
    pub transactions: Vec<u8>,
}

impl TransactionList {
    /// Deserializes from TL format.
    pub fn deserialize(reader: &mut TlReader) -> TlResult<Self> {
        let ids = reader.read_vector_bare(BlockIdExt::deserialize)?;
        let transactions = reader.read_bytes()?;

        Ok(Self { ids, transactions })
    }
}

/// Block transactions list response.
#[derive(Debug, Clone)]
pub struct BlockTransactions {
    /// Block containing the transactions.
    pub block_id: BlockIdExt,
    /// Requested count.
    pub req_count: u32,
    /// Whether the list is incomplete.
    pub incomplete: bool,
    /// Transaction IDs.
    pub ids: Vec<TransactionId>,
    /// Proof as BoC.
    pub proof: Vec<u8>,
}

impl BlockTransactions {
    /// Deserializes from TL format.
    pub fn deserialize(reader: &mut TlReader) -> TlResult<Self> {
        let block_id = BlockIdExt::deserialize(reader)?;
        let req_count = reader.read_u32()?;
        let incomplete = reader.read_bool()?;
        let ids = reader.read_vector_bare(TransactionId::deserialize)?;
        let proof = reader.read_bytes()?;

        Ok(Self {
            block_id,
            req_count,
            incomplete,
            ids,
            proof,
        })
    }
}

/// Config info response.
#[derive(Debug, Clone)]
pub struct ConfigInfo {
    /// Mode flags.
    pub mode: u32,
    /// Block at which config was queried.
    pub block_id: BlockIdExt,
    /// State proof as BoC.
    pub state_proof: Vec<u8>,
    /// Config proof as BoC.
    pub config_proof: Vec<u8>,
}

impl ConfigInfo {
    /// Deserializes from TL format.
    pub fn deserialize(reader: &mut TlReader) -> TlResult<Self> {
        Ok(Self {
            mode: reader.read_u32()?,
            block_id: BlockIdExt::deserialize(reader)?,
            state_proof: reader.read_bytes()?,
            config_proof: reader.read_bytes()?,
        })
    }
}

/// Send message status response.
#[derive(Debug, Clone, Copy)]
pub struct SendMsgStatus {
    /// Status code (1 = success).
    pub status: i32,
}

impl SendMsgStatus {
    /// Deserializes from TL format.
    pub fn deserialize(reader: &mut TlReader) -> TlResult<Self> {
        Ok(Self {
            status: reader.read_i32()?,
        })
    }

    /// Returns true if the message was accepted.
    pub fn is_success(&self) -> bool {
        self.status == 1
    }
}

/// Liteserver error response.
#[derive(Debug, Clone)]
pub struct LiteServerError {
    /// Error code.
    pub code: i32,
    /// Error message.
    pub message: String,
}

impl LiteServerError {
    /// Deserializes from TL format.
    pub fn deserialize(reader: &mut TlReader) -> TlResult<Self> {
        Ok(Self {
            code: reader.read_i32()?,
            message: reader.read_string()?,
        })
    }
}

impl fmt::Display for LiteServerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "LiteServer error {}: {}", self.code, self.message)
    }
}

impl std::error::Error for LiteServerError {}

// ============================================================================
// TVM Stack Types
// ============================================================================

/// TVM stack entry for get method results.
#[derive(Debug, Clone)]
pub enum StackEntry {
    /// Null value.
    Null,
    /// Integer value (up to 257 bits).
    Int(num_bigint::BigInt),
    /// Cell reference.
    Cell(Arc<Cell>),
    /// Cell slice (partial cell).
    Slice {
        cell: Arc<Cell>,
        bits_start: usize,
        bits_len: usize,
        refs_start: usize,
        refs_len: usize,
    },
    /// Cell builder.
    Builder(Arc<Cell>),
    /// Continuation (code reference).
    Continuation(Arc<Cell>),
    /// Tuple of stack entries.
    Tuple(Vec<StackEntry>),
}

impl StackEntry {
    /// Returns the entry as an integer, if it is one.
    pub fn as_int(&self) -> Option<&num_bigint::BigInt> {
        match self {
            StackEntry::Int(n) => Some(n),
            _ => None,
        }
    }

    /// Returns the entry as an i64, if it is an integer that fits.
    pub fn as_i64(&self) -> Option<i64> {
        match self {
            StackEntry::Int(n) => {
                use num_traits::ToPrimitive;
                n.to_i64()
            }
            _ => None,
        }
    }

    /// Returns the entry as a cell, if it is one.
    pub fn as_cell(&self) -> Option<&Arc<Cell>> {
        match self {
            StackEntry::Cell(c) => Some(c),
            _ => None,
        }
    }

    /// Returns the entry as a tuple, if it is one.
    pub fn as_tuple(&self) -> Option<&[StackEntry]> {
        match self {
            StackEntry::Tuple(t) => Some(t),
            _ => None,
        }
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Computes the CRC32 of a method name to get the method ID.
///
/// TON uses CRC16 (XMODEM) of the method name, then stores it as a 32-bit value.
pub fn compute_method_id(method_name: &str) -> u64 {
    let hash = crc16_xmodem(method_name.as_bytes());
    (hash as u64) | 0x10000
}

/// CRC16-XMODEM implementation.
fn crc16_xmodem(data: &[u8]) -> u16 {
    let mut crc: u16 = 0;
    for &byte in data {
        crc ^= (byte as u16) << 8;
        for _ in 0..8 {
            if crc & 0x8000 != 0 {
                crc = (crc << 1) ^ 0x1021;
            } else {
                crc <<= 1;
            }
        }
    }
    crc
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_block_id_masterchain() {
        let block = BlockId::masterchain(12345);
        assert_eq!(block.workchain, -1);
        assert_eq!(block.shard, i64::MIN);
        assert_eq!(block.seqno, 12345);
    }

    #[test]
    fn test_block_id_serialize_deserialize() {
        let block = BlockId::new(0, 0x8000000000000000u64 as i64, 100);

        let mut writer = TlWriter::new();
        block.serialize(&mut writer);

        let mut reader = TlReader::new(writer.as_bytes());
        let decoded = BlockId::deserialize(&mut reader).unwrap();

        assert_eq!(block, decoded);
    }

    #[test]
    fn test_block_id_ext_serialize_deserialize() {
        let block = BlockIdExt::new(
            -1,
            i64::MIN,
            12345,
            [0xAA; 32],
            [0xBB; 32],
        );

        let mut writer = TlWriter::new();
        block.serialize(&mut writer);

        let mut reader = TlReader::new(writer.as_bytes());
        let decoded = BlockIdExt::deserialize(&mut reader).unwrap();

        assert_eq!(block, decoded);
    }

    #[test]
    fn test_account_address_from_raw_string() {
        let addr_str = "0:0000000000000000000000000000000000000000000000000000000000000000";
        let addr = AccountAddress::from_raw_string(addr_str).unwrap();

        assert_eq!(addr.workchain, 0);
        assert_eq!(addr.address, [0u8; 32]);
        assert_eq!(addr.to_raw_string(), addr_str);
    }

    #[test]
    fn test_account_address_serialize_deserialize() {
        let addr = AccountAddress::new(-1, [0xAB; 32]);

        let mut writer = TlWriter::new();
        addr.serialize(&mut writer);

        let mut reader = TlReader::new(writer.as_bytes());
        let decoded = AccountAddress::deserialize(&mut reader).unwrap();

        assert_eq!(addr, decoded);
    }

    #[test]
    fn test_compute_method_id() {
        // "seqno" method ID should be 0x10000 | CRC16("seqno")
        let id = compute_method_id("seqno");
        assert!(id > 0x10000);

        // "get_wallet_data" is a common method
        let id2 = compute_method_id("get_wallet_data");
        assert!(id2 > 0x10000);
    }

    #[test]
    fn test_crc16_xmodem() {
        // Known test vectors
        assert_eq!(crc16_xmodem(b"123456789"), 0x31C3);
        assert_eq!(crc16_xmodem(b""), 0x0000);
    }

    #[test]
    fn test_block_id_display() {
        let block = BlockId::masterchain(12345);
        let s = format!("{}", block);
        assert!(s.contains("-1"));
        assert!(s.contains("12345"));
    }

    #[test]
    fn test_send_msg_status() {
        let status = SendMsgStatus { status: 1 };
        assert!(status.is_success());

        let status2 = SendMsgStatus { status: 0 };
        assert!(!status2.is_success());
    }
}
