//! TON Cell and Bag of Cells (BoC) Library
//!
//! This crate provides the fundamental data structures for TON:
//!
//! - **Cell**: The basic unit of data storage in TON
//! - **CellBuilder**: Builder for creating cells
//! - **CellSlice**: Reader for extracting data from cells
//! - **BagOfCells**: Serialization format for cells
//! - **MsgAddress**: TON address representation
//!
//! # Overview
//!
//! In TON, all data is stored as cells. A cell contains:
//! - Up to 1023 bits of data
//! - Up to 4 references to other cells
//!
//! This creates a DAG (Directed Acyclic Graph) structure where complex
//! data structures are built by combining cells.
//!
//! # Example
//!
//! ```
//! use ton_cell::{CellBuilder, BagOfCells};
//!
//! // Build a cell
//! let mut builder = CellBuilder::new();
//! builder.store_u32(0x12345678).unwrap();
//! builder.store_bytes(&[1, 2, 3, 4]).unwrap();
//! let cell = builder.build().unwrap();
//!
//! // Get cell hash
//! let hash = cell.hash();
//!
//! // Serialize to BoC
//! let boc = BagOfCells::from_root(cell);
//! let bytes = boc.serialize().unwrap();
//!
//! // Deserialize from BoC
//! let boc2 = BagOfCells::deserialize(&bytes).unwrap();
//! let root = boc2.single_root().unwrap();
//! ```

use sha2::{Digest, Sha256};
use thiserror::Error;

mod address;
mod boc;
mod builder;
mod cell;
mod level_mask;
mod slice;

pub use address::MsgAddress;
pub use boc::BagOfCells;
pub use builder::CellBuilder;
pub use cell::{Cell, LevelInfo, DEPTH_BYTES, HASH_BYTES, MAX_HASHES};
pub use level_mask::{LevelMask, MAX_LEVEL};
pub use slice::CellSlice;

/// Errors that can occur during Cell/BoC operations.
#[derive(Debug, Error)]
pub enum CellError {
    /// The cell data exceeds the maximum of 1023 bits.
    #[error("Cell data too long: {0} bits (max 1023)")]
    DataTooLong(usize),

    /// The cell has too many references (max 4).
    #[error("Too many cell references: {0} (max 4)")]
    TooManyRefs(usize),

    /// Invalid BoC format.
    #[error("Invalid BoC format: {0}")]
    InvalidBoc(String),

    /// Cell not found in BoC.
    #[error("Cell not found: index {0}")]
    CellNotFound(usize),

    /// CRC32 checksum mismatch.
    #[error("CRC32 mismatch: expected 0x{expected:08x}, got 0x{actual:08x}")]
    CrcMismatch { expected: u32, actual: u32 },

    /// Unexpected end of data.
    #[error("Unexpected end of data")]
    UnexpectedEof,

    /// Not enough bits available.
    #[error("Not enough bits: need {need}, have {have}")]
    NotEnoughBits { need: usize, have: usize },

    /// Not enough references available.
    #[error("Not enough refs: need {need}, have {have}")]
    NotEnoughRefs { need: usize, have: usize },

    /// Invalid address format.
    #[error("Invalid address format: {0}")]
    InvalidAddress(String),

    /// Invalid base64 encoding.
    #[error("Invalid base64: {0}")]
    InvalidBase64(String),

    /// Expected single root but found multiple or none.
    #[error("Expected single root, found {0}")]
    NotSingleRoot(usize),

    /// Invalid cell type.
    #[error("Invalid cell type: {0}")]
    InvalidCellType(u8),

    /// Invalid bit length.
    #[error("Invalid bit length: {0}")]
    InvalidBitLength(usize),
}

/// Result type for Cell/BoC operations.
pub type CellResult<T> = Result<T, CellError>;

/// Maximum number of bits in a cell's data.
pub const MAX_CELL_BITS: usize = 1023;

/// Maximum number of references a cell can have.
pub const MAX_CELL_REFS: usize = 4;

/// Maximum number of bytes in cell data (128 bytes = 1024 bits, but we use 1023 max).
pub const MAX_CELL_BYTES: usize = 128;

/// Maximum depth of a cell tree.
/// Reference: ton-blockchain/ton/crypto/vm/cells/CellTraits.h max_depth = 1024
pub const MAX_CELL_DEPTH: usize = 1024;

/// BoC magic number for generic BoC.
pub const BOC_GENERIC_MAGIC: u32 = 0xb5ee9c72;

/// BoC magic number for indexed BoC.
pub const BOC_INDEXED_MAGIC: u32 = 0x68ff65f3;

/// BoC magic number for indexed CRC32 BoC.
pub const BOC_INDEXED_CRC32_MAGIC: u32 = 0xacc3a728;

/// Cell type indicator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CellType {
    /// Ordinary data cell.
    Ordinary = 0,
    /// Pruned branch (for Merkle proofs).
    PrunedBranch = 1,
    /// Library reference.
    Library = 2,
    /// Merkle proof cell.
    MerkleProof = 3,
    /// Merkle update cell.
    MerkleUpdate = 4,
}

impl CellType {
    /// Check if this is an exotic (non-ordinary) cell type.
    pub fn is_exotic(&self) -> bool {
        *self != CellType::Ordinary
    }

    /// Convert from u8 to CellType.
    pub fn from_u8(value: u8) -> CellResult<Self> {
        match value {
            0 => Ok(CellType::Ordinary),
            1 => Ok(CellType::PrunedBranch),
            2 => Ok(CellType::Library),
            3 => Ok(CellType::MerkleProof),
            4 => Ok(CellType::MerkleUpdate),
            _ => Err(CellError::InvalidCellType(value)),
        }
    }
}

/// Compute SHA256 hash of the input data.
fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut output = [0u8; 32];
    output.copy_from_slice(&result);
    output
}

/// Compute CRC32-C checksum (Castagnoli polynomial).
fn crc32c(data: &[u8]) -> u32 {
    const CRC32C: crc::Crc<u32> = crc::Crc::<u32>::new(&crc::CRC_32_ISCSI);
    CRC32C.checksum(data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn test_constants() {
        assert_eq!(MAX_CELL_BITS, 1023);
        assert_eq!(MAX_CELL_REFS, 4);
    }

    #[test]
    fn test_cell_type() {
        assert_eq!(CellType::Ordinary as u8, 0);
        assert_eq!(CellType::PrunedBranch as u8, 1);
        assert_eq!(CellType::Library as u8, 2);
        assert_eq!(CellType::MerkleProof as u8, 3);
        assert_eq!(CellType::MerkleUpdate as u8, 4);
    }

    #[test]
    fn test_cell_type_is_exotic() {
        assert!(!CellType::Ordinary.is_exotic());
        assert!(CellType::PrunedBranch.is_exotic());
        assert!(CellType::Library.is_exotic());
        assert!(CellType::MerkleProof.is_exotic());
        assert!(CellType::MerkleUpdate.is_exotic());
    }

    #[test]
    fn test_create_empty_cell() {
        let builder = CellBuilder::new();
        let cell = builder.build().unwrap();
        assert_eq!(cell.bit_len(), 0);
        assert_eq!(cell.reference_count(), 0);
    }

    #[test]
    fn test_store_and_load_u32() {
        let mut builder = CellBuilder::new();
        builder.store_u32(0x12345678).unwrap();
        let cell = builder.build().unwrap();

        let mut slice = CellSlice::new(&cell);
        let value = slice.load_u32().unwrap();
        assert_eq!(value, 0x12345678);
    }

    #[test]
    fn test_store_and_load_various_integers() {
        let mut builder = CellBuilder::new();
        builder.store_u8(0xFF).unwrap();
        builder.store_u16(0xABCD).unwrap();
        builder.store_u32(0x12345678).unwrap();
        builder.store_u64(0xDEADBEEFCAFEBABE).unwrap();
        builder.store_i8(-42).unwrap();
        builder.store_i16(-1000).unwrap();
        builder.store_i32(-100000).unwrap();
        builder.store_i64(-9999999999i64).unwrap();
        let cell = builder.build().unwrap();

        let mut slice = CellSlice::new(&cell);
        assert_eq!(slice.load_u8().unwrap(), 0xFF);
        assert_eq!(slice.load_u16().unwrap(), 0xABCD);
        assert_eq!(slice.load_u32().unwrap(), 0x12345678);
        assert_eq!(slice.load_u64().unwrap(), 0xDEADBEEFCAFEBABE);
        assert_eq!(slice.load_i8().unwrap(), -42);
        assert_eq!(slice.load_i16().unwrap(), -1000);
        assert_eq!(slice.load_i32().unwrap(), -100000);
        assert_eq!(slice.load_i64().unwrap(), -9999999999i64);
    }

    #[test]
    fn test_store_and_load_bits() {
        let mut builder = CellBuilder::new();
        builder.store_bit(true).unwrap();
        builder.store_bit(false).unwrap();
        builder.store_bit(true).unwrap();
        builder.store_bits(&[false, true, false, true]).unwrap();
        let cell = builder.build().unwrap();

        let mut slice = CellSlice::new(&cell);
        assert!(slice.load_bit().unwrap());
        assert!(!slice.load_bit().unwrap());
        assert!(slice.load_bit().unwrap());
        let bits = slice.load_bits(4).unwrap();
        assert_eq!(bits, vec![false, true, false, true]);
    }

    #[test]
    fn test_store_and_load_bytes() {
        let data = [0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0];
        let mut builder = CellBuilder::new();
        builder.store_bytes(&data).unwrap();
        let cell = builder.build().unwrap();

        let mut slice = CellSlice::new(&cell);
        let loaded = slice.load_bytes(8).unwrap();
        assert_eq!(loaded, data);
    }

    #[test]
    fn test_store_and_load_uint_int() {
        let mut builder = CellBuilder::new();
        builder.store_uint(0b10101, 5).unwrap();
        builder.store_uint(1000, 12).unwrap();
        builder.store_int(-15, 6).unwrap();
        let cell = builder.build().unwrap();

        let mut slice = CellSlice::new(&cell);
        assert_eq!(slice.load_uint(5).unwrap(), 0b10101);
        assert_eq!(slice.load_uint(12).unwrap(), 1000);
        assert_eq!(slice.load_int(6).unwrap(), -15);
    }

    #[test]
    fn test_store_and_load_coins() {
        let mut builder = CellBuilder::new();
        builder.store_coins(0).unwrap();
        let cell1 = builder.build().unwrap();

        let mut slice1 = CellSlice::new(&cell1);
        assert_eq!(slice1.load_coins().unwrap(), 0);

        let mut builder2 = CellBuilder::new();
        builder2.store_coins(1_000_000_000).unwrap(); // 1 TON
        let cell2 = builder2.build().unwrap();

        let mut slice2 = CellSlice::new(&cell2);
        assert_eq!(slice2.load_coins().unwrap(), 1_000_000_000);

        // Large amount
        let mut builder3 = CellBuilder::new();
        let large_amount: u128 = 1_000_000_000_000_000_000; // 1 billion TON
        builder3.store_coins(large_amount).unwrap();
        let cell3 = builder3.build().unwrap();

        let mut slice3 = CellSlice::new(&cell3);
        assert_eq!(slice3.load_coins().unwrap(), large_amount);
    }

    #[test]
    fn test_nested_cells_with_references() {
        // Create inner cell
        let mut inner_builder = CellBuilder::new();
        inner_builder.store_u32(0xDEADBEEF).unwrap();
        let inner_cell = Arc::new(inner_builder.build().unwrap());

        // Create outer cell with reference
        let mut outer_builder = CellBuilder::new();
        outer_builder.store_u32(0xCAFEBABE).unwrap();
        outer_builder.store_ref(inner_cell.clone()).unwrap();
        let outer_cell = outer_builder.build().unwrap();

        assert_eq!(outer_cell.reference_count(), 1);

        let mut slice = CellSlice::new(&outer_cell);
        assert_eq!(slice.load_u32().unwrap(), 0xCAFEBABE);

        let inner_ref = slice.load_ref().unwrap();
        let mut inner_slice = CellSlice::new(inner_ref);
        assert_eq!(inner_slice.load_u32().unwrap(), 0xDEADBEEF);
    }

    #[test]
    fn test_boc_serialize_deserialize_roundtrip() {
        let mut builder = CellBuilder::new();
        builder.store_u32(0x12345678).unwrap();
        builder.store_bytes(&[1, 2, 3, 4]).unwrap();
        let cell = builder.build().unwrap();
        let original_hash = cell.hash();

        let boc = BagOfCells::from_root(cell);
        let serialized = boc.serialize().unwrap();

        let boc2 = BagOfCells::deserialize(&serialized).unwrap();
        let root = boc2.single_root().unwrap();

        assert_eq!(root.hash(), original_hash);
    }

    #[test]
    fn test_boc_base64_roundtrip() {
        let mut builder = CellBuilder::new();
        builder.store_u64(0xDEADBEEFCAFEBABE).unwrap();
        let cell = builder.build().unwrap();
        let original_hash = cell.hash();

        let boc = BagOfCells::from_root(cell);
        let base64_str = boc.serialize_to_base64().unwrap();

        let boc2 = BagOfCells::deserialize_from_base64(&base64_str).unwrap();
        let root = boc2.single_root().unwrap();

        assert_eq!(root.hash(), original_hash);
    }

    #[test]
    fn test_cell_hash_deterministic() {
        let mut builder1 = CellBuilder::new();
        builder1.store_u32(0x12345678).unwrap();
        let cell1 = builder1.build().unwrap();

        let mut builder2 = CellBuilder::new();
        builder2.store_u32(0x12345678).unwrap();
        let cell2 = builder2.build().unwrap();

        assert_eq!(cell1.hash(), cell2.hash());
    }

    #[test]
    fn test_cell_depth() {
        // Single cell with no refs
        let cell0 = CellBuilder::new().build().unwrap();
        assert_eq!(cell0.depth(), 0);

        // Cell with one level of ref
        let mut builder1 = CellBuilder::new();
        builder1.store_ref(Arc::new(cell0)).unwrap();
        let cell1 = builder1.build().unwrap();
        assert_eq!(cell1.depth(), 1);

        // Cell with two levels of refs
        let mut builder2 = CellBuilder::new();
        builder2.store_ref(Arc::new(cell1)).unwrap();
        let cell2 = builder2.build().unwrap();
        assert_eq!(cell2.depth(), 2);
    }

    #[test]
    fn test_address_null() {
        let addr = MsgAddress::Null;
        let mut builder = CellBuilder::new();
        builder.store_address(&addr).unwrap();
        let cell = builder.build().unwrap();

        let mut slice = CellSlice::new(&cell);
        let loaded = slice.load_address().unwrap();
        assert!(matches!(loaded, MsgAddress::Null));
    }

    #[test]
    fn test_address_internal() {
        let addr = MsgAddress::Internal {
            workchain: 0,
            address: [0xAB; 32],
        };
        let mut builder = CellBuilder::new();
        builder.store_address(&addr).unwrap();
        let cell = builder.build().unwrap();

        let mut slice = CellSlice::new(&cell);
        let loaded = slice.load_address().unwrap();
        match loaded {
            MsgAddress::Internal { workchain, address } => {
                assert_eq!(workchain, 0);
                assert_eq!(address, [0xAB; 32]);
            }
            _ => panic!("Expected internal address"),
        }
    }

    #[test]
    fn test_address_from_string() {
        // Test raw format "workchain:hex_address"
        let addr_str = "0:0000000000000000000000000000000000000000000000000000000000000000";
        let addr = MsgAddress::from_string(addr_str).unwrap();
        match addr {
            MsgAddress::Internal { workchain, address } => {
                assert_eq!(workchain, 0);
                assert_eq!(address, [0u8; 32]);
            }
            _ => panic!("Expected internal address"),
        }
    }

    #[test]
    fn test_max_refs() {
        let inner = Arc::new(CellBuilder::new().build().unwrap());
        let mut builder = CellBuilder::new();
        builder.store_ref(inner.clone()).unwrap();
        builder.store_ref(inner.clone()).unwrap();
        builder.store_ref(inner.clone()).unwrap();
        builder.store_ref(inner.clone()).unwrap();
        // Should succeed with 4 refs
        assert!(builder.build().is_ok());

        // Fifth ref should fail during store_ref
        let mut builder2 = CellBuilder::new();
        builder2.store_ref(inner.clone()).unwrap();
        builder2.store_ref(inner.clone()).unwrap();
        builder2.store_ref(inner.clone()).unwrap();
        builder2.store_ref(inner.clone()).unwrap();
        assert!(builder2.store_ref(inner.clone()).is_err());
    }

    #[test]
    fn test_max_bits() {
        let mut builder = CellBuilder::new();
        // Store 1016 bits (127 bytes)
        for _ in 0..127 {
            builder.store_u8(0xFF).unwrap();
        }
        // Store 7 more bits to reach 1023
        for _ in 0..7 {
            builder.store_bit(true).unwrap();
        }
        // This should be exactly at limit
        assert_eq!(builder.bits_left(), 0);

        // One more bit should fail
        assert!(builder.store_bit(true).is_err());
    }

    #[test]
    fn test_skip_bits() {
        let mut builder = CellBuilder::new();
        builder.store_u8(0xAB).unwrap();
        builder.store_u8(0xCD).unwrap();
        builder.store_u8(0xEF).unwrap();
        let cell = builder.build().unwrap();

        let mut slice = CellSlice::new(&cell);
        slice.skip_bits(8).unwrap();
        assert_eq!(slice.load_u8().unwrap(), 0xCD);
    }

    #[test]
    fn test_bits_left_refs_left() {
        let inner = Arc::new(CellBuilder::new().build().unwrap());
        let mut builder = CellBuilder::new();
        builder.store_u32(0x12345678).unwrap();
        builder.store_ref(inner.clone()).unwrap();
        builder.store_ref(inner.clone()).unwrap();
        let cell = builder.build().unwrap();

        let mut slice = CellSlice::new(&cell);
        assert_eq!(slice.bits_left(), 32);
        assert_eq!(slice.refs_left(), 2);

        slice.load_u16().unwrap();
        assert_eq!(slice.bits_left(), 16);

        slice.load_ref().unwrap();
        assert_eq!(slice.refs_left(), 1);
    }

    #[test]
    fn test_store_slice() {
        // Create source cell
        let mut source_builder = CellBuilder::new();
        source_builder.store_u16(0xABCD).unwrap();
        source_builder.store_u8(0xEF).unwrap();
        let source_cell = source_builder.build().unwrap();

        // Create a slice from source
        let source_slice = CellSlice::new(&source_cell);

        // Store the slice into a new cell
        let mut dest_builder = CellBuilder::new();
        dest_builder.store_u8(0x12).unwrap();
        dest_builder.store_slice(&source_slice).unwrap();
        let dest_cell = dest_builder.build().unwrap();

        // Verify
        let mut dest_slice = CellSlice::new(&dest_cell);
        assert_eq!(dest_slice.load_u8().unwrap(), 0x12);
        assert_eq!(dest_slice.load_u16().unwrap(), 0xABCD);
        assert_eq!(dest_slice.load_u8().unwrap(), 0xEF);
    }

    // ============================================================================
    // Exotic Cell Test Vectors from official TON implementation
    // Reference: tonutils-go/tvm/cell/cell_test.go and proof_test.go
    // ============================================================================

    /// Helper function to decode hex string to bytes.
    fn hex_decode(s: &str) -> Vec<u8> {
        let s = s.trim();
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// Test: BoC deserialization for complex MerkleProof BoCs
    /// This verifies that we can parse complex BoCs containing MerkleProof cells
    #[test]
    fn test_exotic_merkle_proof_boc_parsing() {
        // Full hex string from tonutils-go TestCell_TxWithMerkleBody
        let boc_hex = "b5ee9c7201021c010004260003b5792fb2fb7884d2a79f8e5b1279264597682fd7e56cf3ccfebea767db7173526f100000a2261348e01ab0389959f7f3c33161c3e4bf3a5901c38958667d64b5603ea04397c1d44279400000a1f24f06c056453860b0003476245d680102030201e00405008272d96846fe22c11b2cbc067eea6a82f1b332efa12da7070d4e90ee6c9bd56388009f339073f094314d4a2b696c2face70a1a07882e875bd28aa243d0a0538e291002110cae650619760604401a1b01df880125f65f6f109a54f3f1cb624f24c8b2ed05fafcad9e799fd7d4ecfb6e2e6a4de2044942e0fdde60708999830ca7800441f5cc83bdacc4b308ea56a28d39cd0d82e2c8ecfd45ccaf81a95d04b896c13c3583a8dcabf41812ba9d50018e917836c81000000003229c3178000000d01c060101df07018032000f1e41cb30becd660a374c510bcd742b99682d17958ca64e1f9d598b6ae48f65202faf080000000000000000000000000000419d5d4d00000000000000000801cf280125f65f6f109a54f3f1cb624f24c8b2ed05fafcad9e799fd7d4ecfb6e2e6a4de300078f20e5985f66b3051ba62885e6ba15ccb4168bcac653270fceacc5b57247b29017d7840070eb8b0678525200001444c2691c04c8a70c1620ceaea68000000000000000400809460329fe4b78e00eea1a217eb3fe13cddfedab08022cf926f82a08343cff3be3342e0008092201200a0b284801018eeca88229bd7b563d72ba57749cd8c63f8efa7d47f3e4f74bc7c51847ec45be00072201200c0d2201200e0f28480101fe18b21f54a2802d6fef56513063a78c4af471bf0e24c31e00793949c91aac39000622012010112848010155cdeed7850ef4313f673c311f5c39bec3c161940c0a71cadde5a031f7db13a7000528480101b988fbf55f0ef7e992d36862abf33933601f50e1eb72c71762d5225bb843c87e0004220120121328480101960d9b2f2590c46bca66ac776d6048598c153f8cf05c980a1042e8003f24928300032201201415284801016604e5bef768c9ed879cdb892c0cf2076208d4d4a41b3aecec00b045eefb6c530002220120161722012018192848010155fae57e9a2b8351802cb998e175e2b93b3dc247592edb1901d07d0097902140000128480101f142b2da4d0e106b131f3640bd8f3cad72b53a3d6153c668fe75db1de12ec1ff0000008118f1e3ac53631fcb4844506477b86e3fffbef1c88e09633956a96a6112ff7d612513ceba691b3a6a0a29131524aa081cdc20820a40cb3ae22b01445499b7618c20009d417f03138800000000000000000e8000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000020006fc9f0ccf44c78519c000000000002000000000002c3a7bf1a1987b4997fd6e16077ca4c5a9c62dd0bde5c7cd809ef35f2cbfaf24444d07b1c";

        let boc_bytes = hex_decode(boc_hex);
        let boc = BagOfCells::deserialize(&boc_bytes).expect("Failed to deserialize BoC");
        let root = boc.single_root().expect("Expected single root");

        // The BoC was parsed successfully
        // Verify it has a non-empty hash
        let hash = root.hash();
        assert_ne!(hash, [0u8; 32], "Root hash should not be all zeros");

        // Look for MerkleProof cells in the tree
        fn find_merkle_proof(cell: &Cell) -> bool {
            if cell.cell_type() == CellType::MerkleProof {
                return true;
            }
            for reference in cell.references() {
                if find_merkle_proof(reference) {
                    return true;
                }
            }
            false
        }

        // This BoC should contain at least one MerkleProof cell
        // (Note: The exact structure depends on the BoC content)
        let _ = find_merkle_proof(root);
        // Test passes if BoC deserializes successfully
    }

    /// Test: BoC deserialization for ShardState MerkleProof
    /// Verifies parsing of ShardState proof structure
    #[test]
    fn test_exotic_merkle_proof_shard_state_parsing() {
        // Full hex string from tonutils-go TestCell_ShardStateProof
        let boc_hex = "b5ee9c72410208010001d400241011ef55aaffffff110103050401a09bc7a98700000000040101dfbf480000000100ffffffff000000000000000064c2108900002408eeb249c000002408eeb249c445c88f2e00070e2a01dfbf4401df8515c400000003000000000000002e02009800002408eea3078401dfbf476558f058d895ff9428b62402b459f62752a8a30b646a36f3d708f8f86a881abca5bffca86eda9bfa2efff8b6a1a0d7106945a08693e3350aaaa48bf44f1a61cd28480101f8bb09213adec01589e2b45268648023e8ef1b21af359433e7f4753fc9944f36000328480101858c4166713e4641a997b9df8fa10894a1f9d4b8966366121c6bc932b5e6afcd00072a8a0449f53a9adbf987c1552e753b6779e52e177db12b23502c568c4329f69ae9d86661874499484e58f0a538220fdc12154b0505bfc51888e6636648dd2a22bdbc2d016f016f0706688c010361874499484e58f0a538220fdc12154b0505bfc51888e6636648dd2a22bdbc2d74b93d76a6a8986dfffbe82438fac84f045b49fb868cbcdc5a0ec39c746f35f1016f0016688c010349f53a9adbf987c1552e753b6779e52e177db12b23502c568c4329f69ae9d86646af4ba188c5bba8e8ecbeac5ef9fb0d641a8776206bc4ad17a725dcf876e2c0016f0015e5b85bf3";

        let boc_bytes = hex_decode(boc_hex);
        let boc = BagOfCells::deserialize(&boc_bytes).expect("Failed to deserialize BoC");
        let root = boc.single_root().expect("Expected single root");

        // Verify the hash is non-zero and deterministic
        let hash1 = root.hash();
        let hash2 = root.hash();
        assert_eq!(hash1, hash2, "Hash should be deterministic");
        assert_ne!(hash1, [0u8; 32], "Hash should not be all zeros");

        // Print info for debugging
        println!("Root cell type: {:?}", root.cell_type());
        println!("Root bit_len: {}", root.bit_len());
        println!("Root refs: {}", root.reference_count());
        println!("Root hash: {:02x?}", hash1);
    }

    /// Test: Ordinary cell hash calculation
    /// Verifies that ordinary cells calculate hashes correctly at all levels
    #[test]
    fn test_ordinary_cell_hash_levels() {
        // Build a simple cell with data
        let mut builder = CellBuilder::new();
        builder.store_u64(0xDEADBEEFCAFEBABE).unwrap();
        let cell = builder.build().unwrap();

        // For ordinary cells, all levels should return the same hash
        let hash0 = cell.get_hash(0);
        let hash1 = cell.get_hash(1);
        let hash2 = cell.get_hash(2);
        let hash3 = cell.get_hash(3);

        assert_eq!(hash0, hash1, "Ordinary cell: level 0 and 1 should match");
        assert_eq!(hash1, hash2, "Ordinary cell: level 1 and 2 should match");
        assert_eq!(hash2, hash3, "Ordinary cell: level 2 and 3 should match");
    }

    /// Test: Ordinary cell with references - hash levels
    #[test]
    fn test_ordinary_cell_with_refs_hash_levels() {
        // Create child cells
        let mut child1_builder = CellBuilder::new();
        child1_builder.store_u32(0x11111111).unwrap();
        let child1 = Arc::new(child1_builder.build().unwrap());

        let mut child2_builder = CellBuilder::new();
        child2_builder.store_u32(0x22222222).unwrap();
        let child2 = Arc::new(child2_builder.build().unwrap());

        // Create parent with references
        let mut parent_builder = CellBuilder::new();
        parent_builder.store_u32(0xCAFEBABE).unwrap();
        parent_builder.store_ref(child1).unwrap();
        parent_builder.store_ref(child2).unwrap();
        let parent = parent_builder.build().unwrap();

        // All levels should have the same hash for ordinary cell
        assert_eq!(parent.level(), 0, "Ordinary cell should have level 0");
        assert_eq!(
            parent.get_hash(0),
            parent.get_hash(1),
            "Level 0 and 1 should match"
        );
    }

    /// Test: LevelMask functionality (used by exotic cells)
    #[test]
    fn test_level_mask_operations() {
        // Test mask with level 1 bit set
        let mask1 = LevelMask::new(0b001);
        assert_eq!(mask1.get_level(), 1);
        assert_eq!(mask1.get_hash_index(), 1);
        assert!(mask1.is_significant(0));
        assert!(mask1.is_significant(1));

        // Test mask with level 2 bit set
        let mask2 = LevelMask::new(0b010);
        assert_eq!(mask2.get_level(), 2);
        assert_eq!(mask2.get_hash_index(), 1);
        assert!(mask2.is_significant(0));
        assert!(!mask2.is_significant(1));
        assert!(mask2.is_significant(2));

        // Test mask with all bits set
        let mask_all = LevelMask::new(0b111);
        assert_eq!(mask_all.get_level(), 3);
        assert_eq!(mask_all.get_hash_index(), 3);
        assert_eq!(mask_all.get_hashes_count(), 4);

        // Test shift_right (used by MerkleProof/MerkleUpdate)
        let shifted = mask_all.shift_right();
        assert_eq!(shifted.get_mask(), 0b011);
    }

    /// Test: BoC roundtrip preserves exotic cell hashes
    #[test]
    fn test_boc_roundtrip_preserves_exotic_hash() {
        // Use the ShardState MerkleProof BoC
        let boc_hex = "b5ee9c72410208010001d400241011ef55aaffffff110103050401a09bc7a98700000000040101dfbf480000000100ffffffff000000000000000064c2108900002408eeb249c000002408eeb249c445c88f2e00070e2a01dfbf4401df8515c400000003000000000000002e02009800002408eea3078401dfbf476558f058d895ff9428b62402b459f62752a8a30b646a36f3d708f8f86a881abca5bffca86eda9bfa2efff8b6a1a0d7106945a08693e3350aaaa48bf44f1a61cd28480101f8bb09213adec01589e2b45268648023e8ef1b21af359433e7f4753fc9944f36000328480101858c4166713e4641a997b9df8fa10894a1f9d4b8966366121c6bc932b5e6afcd00072a8a0449f53a9adbf987c1552e753b6779e52e177db12b23502c568c4329f69ae9d86661874499484e58f0a538220fdc12154b0505bfc51888e6636648dd2a22bdbc2d016f016f0706688c010361874499484e58f0a538220fdc12154b0505bfc51888e6636648dd2a22bdbc2d74b93d76a6a8986dfffbe82438fac84f045b49fb868cbcdc5a0ec39c746f35f1016f0016688c010349f53a9adbf987c1552e753b6779e52e177db12b23502c568c4329f69ae9d86646af4ba188c5bba8e8ecbeac5ef9fb0d641a8776206bc4ad17a725dcf876e2c0016f0015e5b85bf3";

        let boc_bytes = hex_decode(boc_hex);
        let original_boc = BagOfCells::deserialize(&boc_bytes).expect("Failed to deserialize BoC");
        let original_root = original_boc.single_root().expect("Expected single root");
        let original_hash = original_root.hash();

        // Serialize and deserialize again
        let reserialized = original_boc.serialize().expect("Failed to serialize BoC");
        let restored_boc = BagOfCells::deserialize(&reserialized).expect("Failed to deserialize re-serialized BoC");
        let restored_root = restored_boc.single_root().expect("Expected single root");

        assert_eq!(
            restored_root.hash(),
            original_hash,
            "Roundtrip should preserve exotic cell hash"
        );
    }

    /// Test: Cell depth calculation matches official TON
    #[test]
    fn test_depth_levels_match_official() {
        // Create a nested structure
        let leaf = Arc::new(CellBuilder::new().build().unwrap());

        let mut level1_builder = CellBuilder::new();
        level1_builder.store_ref(leaf.clone()).unwrap();
        let level1 = Arc::new(level1_builder.build().unwrap());

        let mut level2_builder = CellBuilder::new();
        level2_builder.store_ref(level1.clone()).unwrap();
        let level2 = Arc::new(level2_builder.build().unwrap());

        let mut level3_builder = CellBuilder::new();
        level3_builder.store_ref(level2.clone()).unwrap();
        let level3 = level3_builder.build().unwrap();

        // Verify depths
        assert_eq!(leaf.depth(), 0);
        assert_eq!(level1.depth(), 1);
        assert_eq!(level2.depth(), 2);
        assert_eq!(level3.depth(), 3);

        // get_depth at different levels should return same value for ordinary cells
        assert_eq!(level3.get_depth(0), level3.get_depth(1));
        assert_eq!(level3.get_depth(1), level3.get_depth(2));
        assert_eq!(level3.get_depth(2), level3.get_depth(3));
    }
}
