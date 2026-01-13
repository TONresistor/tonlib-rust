//! Cell implementation for TON.
//!
//! A Cell is the fundamental data unit in TON, containing up to 1023 bits
//! of data and up to 4 references to other cells.
//!
//! ## Multi-level Hashing
//!
//! TON cells support multi-level hashing for Merkle proof operations.
//! Each cell can have hashes at levels 0-3, determined by its LevelMask.
//!
//! Reference: ton-blockchain/ton/crypto/vm/cells/DataCell.cpp

use std::sync::Arc;

use crate::{sha256, CellType, LevelMask, MAX_CELL_BITS, MAX_CELL_REFS, MAX_LEVEL};

/// Hash size in bytes (SHA256).
pub const HASH_BYTES: usize = 32;

/// Depth size in bytes.
pub const DEPTH_BYTES: usize = 2;

/// Maximum number of hashes stored per cell (levels 0-3 + 1).
pub const MAX_HASHES: usize = 4;

/// Level info containing hash and depth at a specific level.
#[derive(Debug, Clone, Copy)]
pub struct LevelInfo {
    pub hash: [u8; HASH_BYTES],
    pub depth: u16,
}

impl Default for LevelInfo {
    fn default() -> Self {
        Self {
            hash: [0u8; HASH_BYTES],
            depth: 0,
        }
    }
}

/// A TON Cell - the basic unit of data storage.
///
/// Cells form a DAG (Directed Acyclic Graph) where each cell can reference
/// up to 4 other cells. The cell hash uniquely identifies the cell and its
/// entire subtree.
///
/// ## Level-based Hashing
///
/// Different cell types have different level behaviors:
/// - **Ordinary**: level_mask = OR of all children's masks, level = 0
/// - **PrunedBranch**: level_mask stored in data[1], hashes pre-stored in data
/// - **MerkleProof**: level_mask = child.level_mask >> 1
/// - **MerkleUpdate**: level_mask = (child1.mask | child2.mask) >> 1
#[derive(Debug, Clone)]
pub struct Cell {
    /// Raw data bytes (may contain partial byte at the end).
    pub(crate) data: Vec<u8>,
    /// Number of bits stored in data.
    pub(crate) bit_len: usize,
    /// References to child cells.
    pub(crate) references: Vec<Arc<Cell>>,
    /// Type of cell (ordinary, pruned branch, etc.).
    pub(crate) cell_type: CellType,
    /// Level mask indicating which levels have meaningful hashes.
    pub(crate) level_mask: LevelMask,
    /// Cached level info (hashes and depths at each level).
    /// Index 0 = level 0, etc. Number of entries = level_mask.get_hashes_count()
    pub(crate) level_info: Vec<LevelInfo>,
}

impl Cell {
    /// Create a new cell with the given parameters.
    ///
    /// This is typically called by CellBuilder::build().
    /// The cell will calculate its level_mask and hashes lazily or on creation.
    pub(crate) fn new(
        data: Vec<u8>,
        bit_len: usize,
        references: Vec<Arc<Cell>>,
        cell_type: CellType,
    ) -> Self {
        debug_assert!(bit_len <= MAX_CELL_BITS);
        debug_assert!(references.len() <= MAX_CELL_REFS);

        let mut cell = Cell {
            data,
            bit_len,
            references,
            cell_type,
            level_mask: LevelMask::new(0),
            level_info: Vec::new(),
        };

        // Calculate level mask and hashes
        cell.calculate_hashes();
        cell
    }

    /// Create an empty cell.
    pub fn empty() -> Self {
        Self::new(Vec::new(), 0, Vec::new(), CellType::Ordinary)
    }

    /// Calculate level mask based on cell type and children.
    fn compute_level_mask(&self) -> LevelMask {
        match self.cell_type {
            CellType::Ordinary => {
                // Ordinary: OR of all children's level masks
                let mut mask = LevelMask::new(0);
                for reference in &self.references {
                    mask = mask.apply_or(reference.level_mask);
                }
                mask
            }
            CellType::PrunedBranch => {
                // PrunedBranch: level mask is stored in data[1]
                // Format: data[0] = cell_type (0x01), data[1] = level_mask
                if self.data.len() >= 2 {
                    LevelMask::new(self.data[1])
                } else {
                    LevelMask::new(0)
                }
            }
            CellType::MerkleProof => {
                // MerkleProof: child's level mask shifted right
                if let Some(child) = self.references.first() {
                    child.level_mask.shift_right()
                } else {
                    LevelMask::new(0)
                }
            }
            CellType::MerkleUpdate => {
                // MerkleUpdate: OR of both children's masks, then shift right
                let mask = self.references.iter().fold(LevelMask::new(0), |acc, r| {
                    acc.apply_or(r.level_mask)
                });
                mask.shift_right()
            }
            CellType::Library => LevelMask::new(0),
        }
    }

    /// Calculate hashes and depths for all levels.
    ///
    /// This implements the official TON hash calculation algorithm from DataCell.cpp.
    fn calculate_hashes(&mut self) {
        self.level_mask = self.compute_level_mask();
        let hashes_count = self.level_mask.get_hashes_count() as usize;
        self.level_info = vec![LevelInfo::default(); hashes_count];

        let is_merkle = matches!(
            self.cell_type,
            CellType::MerkleProof | CellType::MerkleUpdate
        );

        // Calculate for each level from 0 to max_level
        let mut hash_index = 0usize;
        for level in 0..=MAX_LEVEL {
            if !self.level_mask.is_significant(level) && level != 0 {
                continue;
            }

            // Calculate depth at this level
            let depth = self.calculate_depth_at_level(level, is_merkle);

            // Calculate hash at this level
            let hash = self.calculate_hash_at_level(level, hash_index, is_merkle);

            if hash_index < self.level_info.len() {
                self.level_info[hash_index] = LevelInfo { hash, depth };
            }

            if self.level_mask.is_significant(level) || level == 0 {
                hash_index += 1;
            }

            if hash_index >= hashes_count {
                break;
            }
        }
    }

    /// Calculate depth at a specific level.
    fn calculate_depth_at_level(&self, level: u8, is_merkle: bool) -> u16 {
        match self.cell_type {
            CellType::PrunedBranch => {
                // For pruned branch, depth is stored in data after hashes
                self.get_pruned_depth(level)
            }
            _ => {
                // For ordinary and merkle cells
                if self.references.is_empty() {
                    0
                } else {
                    let child_level = if is_merkle { level + 1 } else { level };
                    let max_child_depth = self
                        .references
                        .iter()
                        .map(|r| r.get_depth(child_level))
                        .max()
                        .unwrap_or(0);
                    max_child_depth.saturating_add(1)
                }
            }
        }
    }

    /// Calculate hash at a specific level.
    fn calculate_hash_at_level(&self, level: u8, hash_index: usize, is_merkle: bool) -> [u8; HASH_BYTES] {
        // For pruned branch at non-max level, extract hash from data
        if self.cell_type == CellType::PrunedBranch && level < self.level_mask.get_level() {
            return self.get_pruned_hash(level);
        }

        // Build representation for hashing
        let mut repr = Vec::with_capacity(2 + 128 + self.references.len() * (DEPTH_BYTES + HASH_BYTES));

        // Descriptor bytes
        let (d1, d2) = self.descriptors_at_level(level);
        repr.push(d1);
        repr.push(d2);

        // Data: either previous level's hash or raw data
        if level > 0 && hash_index > 0 && !matches!(self.cell_type, CellType::PrunedBranch) {
            // Use previous level's hash
            repr.extend_from_slice(&self.level_info[hash_index - 1].hash);
        } else {
            // Use raw data with completion tag
            repr.extend_from_slice(&self.data_with_completion_tag());
        }

        // Child depths
        let child_level = if is_merkle { level + 1 } else { level };
        for reference in &self.references {
            let depth = reference.get_depth(child_level);
            repr.push((depth >> 8) as u8);
            repr.push(depth as u8);
        }

        // Child hashes
        for reference in &self.references {
            repr.extend_from_slice(&reference.get_hash(child_level));
        }

        sha256(&repr)
    }

    /// Get hash stored in pruned branch data at a specific level.
    fn get_pruned_hash(&self, level: u8) -> [u8; HASH_BYTES] {
        // PrunedBranch format:
        // data[0] = cell_type (0x01)
        // data[1] = level_mask
        // data[2..2+32*n] = hashes for each significant level
        // data[2+32*n..] = depths for each significant level

        let mask = self.level_mask;
        let hashes_before = mask.apply(level).get_hash_index() as usize;
        let offset = 2 + hashes_before * HASH_BYTES;

        if offset + HASH_BYTES <= self.data.len() {
            let mut hash = [0u8; HASH_BYTES];
            hash.copy_from_slice(&self.data[offset..offset + HASH_BYTES]);
            hash
        } else {
            [0u8; HASH_BYTES]
        }
    }

    /// Get depth stored in pruned branch data at a specific level.
    fn get_pruned_depth(&self, level: u8) -> u16 {
        let mask = self.level_mask;
        let total_hashes = mask.get_hashes_count() as usize;
        let depths_offset = 2 + total_hashes * HASH_BYTES;
        let level_index = mask.apply(level).get_hash_index() as usize;
        let offset = depths_offset + level_index * DEPTH_BYTES;

        if offset + DEPTH_BYTES <= self.data.len() {
            u16::from_be_bytes([self.data[offset], self.data[offset + 1]])
        } else {
            0
        }
    }

    /// Get the SHA256 hash of this cell at level 0 (default).
    ///
    /// This is the standard hash used for identifying cells.
    pub fn hash(&self) -> [u8; HASH_BYTES] {
        self.get_hash(0)
    }

    /// Get the hash at a specific level.
    ///
    /// For ordinary cells, all levels return the same hash.
    /// For exotic cells, different levels may have different hashes.
    ///
    /// Implementation matches official TON: level_info[min(level_, level)]
    /// Reference: ton-blockchain/ton/crypto/vm/cells/DataCell.h
    pub fn get_hash(&self, level: u8) -> [u8; HASH_BYTES] {
        let level = level.min(MAX_LEVEL);
        let cell_level = self.level_mask.get_level();

        // Hash index is min(cell_level, requested_level)
        // This matches official TON: level_info()[std::min<td::uint32>(level_, level)].hash
        let hash_index = (level.min(cell_level)) as usize;

        if hash_index < self.level_info.len() {
            self.level_info[hash_index].hash
        } else if !self.level_info.is_empty() {
            // Fallback to last available hash
            self.level_info[self.level_info.len() - 1].hash
        } else {
            [0u8; HASH_BYTES]
        }
    }

    /// Get the depth at a specific level.
    ///
    /// Implementation matches official TON: level_info[min(level_, level)]
    pub fn get_depth(&self, level: u8) -> u16 {
        let level = level.min(MAX_LEVEL);
        let cell_level = self.level_mask.get_level();

        // Depth index is min(cell_level, requested_level)
        let hash_index = (level.min(cell_level)) as usize;

        if hash_index < self.level_info.len() {
            self.level_info[hash_index].depth
        } else if !self.level_info.is_empty() {
            self.level_info[self.level_info.len() - 1].depth
        } else {
            0
        }
    }

    /// Get the cell representation for hashing (at level 0).
    pub fn cell_representation(&self) -> Vec<u8> {
        self.cell_representation_at_level(0)
    }

    /// Get the cell representation for hashing at a specific level.
    pub fn cell_representation_at_level(&self, level: u8) -> Vec<u8> {
        let mut repr = Vec::new();

        // Descriptor bytes
        let (d1, d2) = self.descriptors_at_level(level);
        repr.push(d1);
        repr.push(d2);

        // Data with completion tag
        repr.extend_from_slice(&self.data_with_completion_tag());

        let is_merkle = matches!(
            self.cell_type,
            CellType::MerkleProof | CellType::MerkleUpdate
        );
        let child_level = if is_merkle { level + 1 } else { level };

        // For each reference: depth (2 bytes, big-endian)
        for reference in &self.references {
            let depth = reference.get_depth(child_level);
            repr.push((depth >> 8) as u8);
            repr.push(depth as u8);
        }

        // For each reference: hash (32 bytes)
        for reference in &self.references {
            repr.extend_from_slice(&reference.get_hash(child_level));
        }

        repr
    }

    /// Get the descriptor bytes (d1, d2) for this cell at level 0.
    pub fn descriptors(&self) -> (u8, u8) {
        self.descriptors_at_level(0)
    }

    /// Get the descriptor bytes (d1, d2) at a specific level.
    ///
    /// According to official TON code:
    /// d1 = refs_count + 8*is_exotic + 32*level_mask.apply(level).get_mask()
    /// d2 = ceil(bit_len / 8) + floor(bit_len / 8)
    pub fn descriptors_at_level(&self, level: u8) -> (u8, u8) {
        let refs_count = self.references.len() as u8;
        let is_exotic = if self.cell_type.is_exotic() { 8 } else { 0 };

        // Official formula: level_mask.apply(level).get_mask() << 5
        let applied_mask = self.level_mask.apply(level).get_mask();
        let level_bits = applied_mask << 5;

        let d1 = refs_count + is_exotic + level_bits;

        // d2 = ceil(bit_len / 8) + floor(bit_len / 8)
        let d2 = (self.bit_len.div_ceil(8) + self.bit_len / 8) as u8;

        (d1, d2)
    }

    /// Get data with completion tag.
    ///
    /// If bit_len is not byte-aligned, the last byte has a completion tag:
    /// the remaining bits are filled with a 1 followed by 0s.
    pub fn data_with_completion_tag(&self) -> Vec<u8> {
        if self.bit_len == 0 {
            return Vec::new();
        }

        let remainder = self.bit_len % 8;
        if remainder == 0 {
            // Byte-aligned, no completion tag needed
            self.data.clone()
        } else {
            // Add completion tag
            let mut result = self.data.clone();
            if let Some(last) = result.last_mut() {
                // Set the bit after the last data bit to 1, rest are already 0
                let mask = 1 << (7 - remainder);
                *last |= mask;
            }
            result
        }
    }

    /// Get the depth of this cell at level 0.
    ///
    /// Depth is 0 for cells with no references, otherwise it's
    /// 1 + max(depth of all references).
    pub fn depth(&self) -> u16 {
        self.get_depth(0)
    }

    /// Get the level of this cell.
    ///
    /// This is derived from the level mask.
    pub fn level(&self) -> u8 {
        self.level_mask.get_level()
    }

    /// Get the level mask.
    pub fn level_mask(&self) -> LevelMask {
        self.level_mask
    }

    /// Get the raw data bytes.
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// Get the number of bits in this cell.
    pub fn bit_len(&self) -> usize {
        self.bit_len
    }

    /// Get all references to child cells.
    pub fn references(&self) -> &[Arc<Cell>] {
        &self.references
    }

    /// Get a reference by index.
    pub fn reference(&self, index: usize) -> Option<&Arc<Cell>> {
        self.references.get(index)
    }

    /// Get the number of references.
    pub fn reference_count(&self) -> usize {
        self.references.len()
    }

    /// Get the cell type.
    pub fn cell_type(&self) -> CellType {
        self.cell_type
    }

    /// Check if this is an ordinary cell.
    pub fn is_ordinary(&self) -> bool {
        self.cell_type == CellType::Ordinary
    }

    /// Check if this is an exotic cell.
    pub fn is_exotic(&self) -> bool {
        self.cell_type.is_exotic()
    }

    /// Get the number of bytes needed to store the data (rounded up).
    pub fn byte_len(&self) -> usize {
        self.bit_len.div_ceil(8)
    }

    /// Get a specific bit from the cell data.
    ///
    /// Returns None if the index is out of bounds.
    pub fn get_bit(&self, index: usize) -> Option<bool> {
        if index >= self.bit_len {
            return None;
        }

        let byte_index = index / 8;
        let bit_index = 7 - (index % 8);

        Some((self.data[byte_index] >> bit_index) & 1 == 1)
    }
}

impl PartialEq for Cell {
    fn eq(&self, other: &Self) -> bool {
        self.hash() == other.hash()
    }
}

impl Eq for Cell {}

impl std::hash::Hash for Cell {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.hash().hash(state);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_cell() {
        let cell = Cell::empty();
        assert_eq!(cell.bit_len(), 0);
        assert_eq!(cell.reference_count(), 0);
        assert_eq!(cell.depth(), 0);
        assert_eq!(cell.level(), 0);
        assert!(cell.is_ordinary());
    }

    #[test]
    fn test_cell_descriptors() {
        // Empty cell
        let cell = Cell::empty();
        let (d1, d2) = cell.descriptors();
        assert_eq!(d1, 0); // 0 refs, not exotic, level 0
        assert_eq!(d2, 0); // 0 bits

        // Cell with data
        let cell = Cell::new(vec![0xFF], 8, vec![], CellType::Ordinary);
        let (d1, d2) = cell.descriptors();
        assert_eq!(d1, 0);
        assert_eq!(d2, 2); // ceil(8/8) + floor(8/8) = 1 + 1 = 2

        // Cell with 5 bits
        let cell = Cell::new(vec![0b11111000], 5, vec![], CellType::Ordinary);
        let (d1_5bits, d2_5bits) = cell.descriptors();
        assert_eq!(d1_5bits, 0); // 0 refs, not exotic, level 0
        assert_eq!(d2_5bits, 1); // ceil(5/8) + floor(5/8) = 1 + 0 = 1
    }

    #[test]
    fn test_data_with_completion_tag() {
        // Byte-aligned data
        let cell = Cell::new(vec![0xFF], 8, vec![], CellType::Ordinary);
        assert_eq!(cell.data_with_completion_tag(), vec![0xFF]);

        // 5 bits of data (11111)
        let cell = Cell::new(vec![0b11111000], 5, vec![], CellType::Ordinary);
        // Completion tag: set bit 6-5=2 (0-indexed from left)
        // 11111 + 1 + 00 = 11111100
        assert_eq!(cell.data_with_completion_tag(), vec![0b11111100]);
    }

    #[test]
    fn test_hash_caching() {
        let cell = Cell::new(vec![0x12, 0x34, 0x56, 0x78], 32, vec![], CellType::Ordinary);

        // Hash should be pre-calculated
        assert!(!cell.level_info.is_empty());

        // Multiple calls should return the same hash
        let hash1 = cell.hash();
        let hash2 = cell.hash();
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_level_mask_ordinary() {
        // Ordinary cell with no refs has level_mask = 0
        let cell = Cell::new(vec![0xFF], 8, vec![], CellType::Ordinary);
        assert_eq!(cell.level_mask().get_mask(), 0);
        assert_eq!(cell.level(), 0);
    }

    #[test]
    fn test_depth_calculation() {
        // Cell with no refs
        let cell0 = Cell::new(vec![], 0, vec![], CellType::Ordinary);
        assert_eq!(cell0.depth(), 0);

        // Cell with one ref
        let cell1 = Cell::new(vec![], 0, vec![Arc::new(cell0.clone())], CellType::Ordinary);
        assert_eq!(cell1.depth(), 1);

        // Cell with nested refs
        let cell2 = Cell::new(vec![], 0, vec![Arc::new(cell1)], CellType::Ordinary);
        assert_eq!(cell2.depth(), 2);
    }

    #[test]
    fn test_exotic_cell_detection() {
        let ordinary = Cell::new(vec![], 0, vec![], CellType::Ordinary);
        assert!(ordinary.is_ordinary());
        assert!(!ordinary.is_exotic());

        let exotic = Cell::new(vec![0x01, 0x00], 16, vec![], CellType::PrunedBranch);
        assert!(!exotic.is_ordinary());
        assert!(exotic.is_exotic());
    }
}
