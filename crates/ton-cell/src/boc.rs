//! Bag of Cells (BoC) serialization format.
//!
//! BoC is the standard serialization format for TON cells. It efficiently
//! encodes a DAG of cells with deduplication and optional CRC32 checksum.

use std::collections::HashMap;
use std::sync::Arc;

use crate::{crc32c, Cell, CellError, CellResult, CellType, BOC_GENERIC_MAGIC, BOC_INDEXED_MAGIC, BOC_INDEXED_CRC32_MAGIC};

/// Bag of Cells - a serialized collection of cells.
///
/// BoC is the standard way to serialize cells in TON. It supports:
/// - Multiple root cells
/// - Cell deduplication (cells with same hash are stored once)
/// - Optional CRC32 checksum for integrity
/// - Optional index for fast cell lookup
#[derive(Debug, Clone)]
pub struct BagOfCells {
    /// Root cells.
    roots: Vec<Arc<Cell>>,
}

impl BagOfCells {
    /// Create a new BoC with the given root cells.
    pub fn new(roots: Vec<Arc<Cell>>) -> Self {
        BagOfCells { roots }
    }

    /// Create a BoC with a single root cell.
    pub fn from_root(root: Cell) -> Self {
        BagOfCells {
            roots: vec![Arc::new(root)],
        }
    }

    /// Get all root cells.
    pub fn roots(&self) -> &[Arc<Cell>] {
        &self.roots
    }

    /// Get a single root cell (errors if not exactly one root).
    pub fn single_root(&self) -> CellResult<&Arc<Cell>> {
        if self.roots.len() != 1 {
            return Err(CellError::NotSingleRoot(self.roots.len()));
        }
        Ok(&self.roots[0])
    }

    /// Get the number of root cells.
    pub fn root_count(&self) -> usize {
        self.roots.len()
    }

    /// Serialize the BoC to bytes.
    ///
    /// Uses the generic BoC format with CRC32 checksum.
    pub fn serialize(&self) -> CellResult<Vec<u8>> {
        self.serialize_with_options(true, false)
    }

    /// Serialize with options.
    ///
    /// # Arguments
    /// * `with_crc` - Include CRC32 checksum
    /// * `with_index` - Include cell index (for faster deserialization)
    pub fn serialize_with_options(&self, with_crc: bool, with_index: bool) -> CellResult<Vec<u8>> {
        if self.roots.is_empty() {
            return Err(CellError::InvalidBoc("No root cells".to_string()));
        }

        // Collect all cells in topological order (children before parents)
        let cells = self.collect_cells_topological();
        let cell_count = cells.len();

        // Build hash to index map
        let hash_to_index: HashMap<[u8; 32], usize> = cells
            .iter()
            .enumerate()
            .map(|(i, c)| (c.hash(), i))
            .collect();

        // Calculate root indices
        let root_indices: Vec<usize> = self
            .roots
            .iter()
            .map(|r| *hash_to_index.get(&r.hash()).unwrap())
            .collect();

        // Serialize cells and calculate total size
        let mut cell_data: Vec<Vec<u8>> = Vec::with_capacity(cell_count);
        let mut total_cells_size = 0usize;

        for cell in &cells {
            let serialized = Self::serialize_cell(cell, &hash_to_index)?;
            total_cells_size += serialized.len();
            cell_data.push(serialized);
        }

        // Calculate size parameters
        let size_bytes = Self::bytes_needed(cell_count);
        let off_bytes = Self::bytes_needed(total_cells_size);

        // Build the BoC
        let mut result = Vec::new();

        // Magic number (4 bytes)
        result.extend_from_slice(&BOC_GENERIC_MAGIC.to_be_bytes());

        // Flags byte: has_idx (bit 7) | has_crc (bit 6) | has_cache_bits (bit 5) | flags (bits 4-3) | size_bytes (bits 2-0)
        let flags: u8 = (if with_index { 1 << 7 } else { 0 })
            | (if with_crc { 1 << 6 } else { 0 })
            | (size_bytes as u8);
        result.push(flags);

        // Off bytes (1 byte)
        result.push(off_bytes as u8);

        // Cells count
        Self::write_uint(&mut result, cell_count as u64, size_bytes);

        // Roots count
        Self::write_uint(&mut result, self.roots.len() as u64, size_bytes);

        // Absent count (always 0 for us)
        Self::write_uint(&mut result, 0, size_bytes);

        // Total cells size
        Self::write_uint(&mut result, total_cells_size as u64, off_bytes);

        // Root indices
        for idx in &root_indices {
            Self::write_uint(&mut result, *idx as u64, size_bytes);
        }

        // Index (if requested)
        if with_index {
            let mut offset = 0usize;
            for data in &cell_data {
                Self::write_uint(&mut result, offset as u64, off_bytes);
                offset += data.len();
            }
        }

        // Cell data
        for data in cell_data {
            result.extend_from_slice(&data);
        }

        // CRC32 (if requested)
        if with_crc {
            let crc = crc32c(&result);
            result.extend_from_slice(&crc.to_le_bytes());
        }

        Ok(result)
    }

    /// Serialize to base64 string.
    pub fn serialize_to_base64(&self) -> CellResult<String> {
        let bytes = self.serialize()?;
        Ok(base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            &bytes,
        ))
    }

    /// Deserialize from bytes.
    ///
    /// Supports all three BoC formats:
    /// - `0xb5ee9c72` - Generic BoC (serialized_boc)
    /// - `0x68ff65f3` - Indexed BoC (serialized_boc_idx)
    /// - `0xacc3a728` - Indexed BoC with CRC32C (serialized_boc_idx_crc32c)
    pub fn deserialize(data: &[u8]) -> CellResult<Self> {
        if data.len() < 5 {
            return Err(CellError::UnexpectedEof);
        }

        let mut offset = 0;

        // Read magic number
        let magic = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
        offset += 4;

        // Determine format based on magic number
        let (has_idx, has_crc, size_bytes) = match magic {
            BOC_GENERIC_MAGIC => {
                // Generic format: has flexible flags
                let flags = data[offset];
                offset += 1;
                let has_idx = (flags & 0x80) != 0;
                let has_crc = (flags & 0x40) != 0;
                let _has_cache_bits = (flags & 0x20) != 0;
                let size_bytes = (flags & 0x07) as usize;
                (has_idx, has_crc, size_bytes)
            }
            BOC_INDEXED_MAGIC => {
                // Indexed format without CRC: always has index, never has CRC
                let size_bytes = data[offset] as usize;
                offset += 1;
                (true, false, size_bytes)
            }
            BOC_INDEXED_CRC32_MAGIC => {
                // Indexed format with CRC32C: always has index and CRC
                let size_bytes = data[offset] as usize;
                offset += 1;
                (true, true, size_bytes)
            }
            _ => {
                return Err(CellError::InvalidBoc(format!(
                    "Invalid magic: {:08x}, expected one of {:08x}, {:08x}, {:08x}",
                    magic, BOC_GENERIC_MAGIC, BOC_INDEXED_MAGIC, BOC_INDEXED_CRC32_MAGIC
                )));
            }
        };

        // Read off_bytes
        let off_bytes = data[offset] as usize;
        offset += 1;

        // Read counts
        let cells_count = Self::read_uint(data, &mut offset, size_bytes)? as usize;
        let roots_count = Self::read_uint(data, &mut offset, size_bytes)? as usize;
        let _absent_count = Self::read_uint(data, &mut offset, size_bytes)? as usize;
        let total_cells_size = Self::read_uint(data, &mut offset, off_bytes)? as usize;

        // Read root indices
        let mut root_indices = Vec::with_capacity(roots_count);
        for _ in 0..roots_count {
            root_indices.push(Self::read_uint(data, &mut offset, size_bytes)? as usize);
        }

        // Skip index if present
        if has_idx {
            offset += cells_count * off_bytes;
        }

        // Calculate CRC check range
        let data_end = if has_crc {
            data.len() - 4
        } else {
            data.len()
        };

        // Verify CRC if present
        if has_crc {
            let expected_crc = u32::from_le_bytes([
                data[data_end],
                data[data_end + 1],
                data[data_end + 2],
                data[data_end + 3],
            ]);
            let actual_crc = crc32c(&data[..data_end]);
            if expected_crc != actual_crc {
                return Err(CellError::CrcMismatch {
                    expected: expected_crc,
                    actual: actual_crc,
                });
            }
        }

        // Parse cells
        let cells_data = &data[offset..offset + total_cells_size];
        let cells = Self::parse_cells(cells_data, cells_count, size_bytes)?;

        // Get root cells
        let roots: Vec<Arc<Cell>> = root_indices
            .iter()
            .map(|&idx| {
                cells
                    .get(idx)
                    .cloned()
                    .ok_or(CellError::CellNotFound(idx))
            })
            .collect::<CellResult<Vec<_>>>()?;

        Ok(BagOfCells { roots })
    }

    /// Deserialize from base64 string.
    pub fn deserialize_from_base64(base64_str: &str) -> CellResult<Self> {
        let bytes = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            base64_str.trim(),
        )
        .map_err(|e| CellError::InvalidBase64(e.to_string()))?;

        Self::deserialize(&bytes)
    }

    /// Deserialize from hex string.
    pub fn deserialize_from_hex(hex_str: &str) -> CellResult<Self> {
        let hex_str = hex_str.trim();
        let bytes: Vec<u8> = (0..hex_str.len())
            .step_by(2)
            .map(|i| {
                u8::from_str_radix(&hex_str[i..i + 2], 16)
                    .map_err(|_| CellError::InvalidBoc("invalid hex string".to_string()))
            })
            .collect::<CellResult<Vec<u8>>>()?;

        Self::deserialize(&bytes)
    }

    /// Collect all cells in topological order (children first).
    fn collect_cells_topological(&self) -> Vec<Arc<Cell>> {
        let mut cells: Vec<Arc<Cell>> = Vec::new();
        let mut visited: HashMap<[u8; 32], usize> = HashMap::new();

        for root in &self.roots {
            Self::collect_cell_recursive(root, &mut cells, &mut visited);
        }

        cells
    }

    /// Recursively collect cells (depth-first, post-order).
    fn collect_cell_recursive(
        cell: &Arc<Cell>,
        cells: &mut Vec<Arc<Cell>>,
        visited: &mut HashMap<[u8; 32], usize>,
    ) {
        let hash = cell.hash();
        if visited.contains_key(&hash) {
            return;
        }

        // Visit children first
        for reference in cell.references() {
            Self::collect_cell_recursive(reference, cells, visited);
        }

        // Add this cell
        let index = cells.len();
        visited.insert(hash, index);
        cells.push(cell.clone());
    }

    /// Serialize a single cell.
    fn serialize_cell(cell: &Cell, hash_to_index: &HashMap<[u8; 32], usize>) -> CellResult<Vec<u8>> {
        let mut result = Vec::new();

        // Descriptor bytes
        let (d1, d2) = cell.descriptors();
        result.push(d1);
        result.push(d2);

        // Data with completion tag
        result.extend_from_slice(&cell.data_with_completion_tag());

        // Reference indices
        let ref_size = Self::bytes_needed(hash_to_index.len());
        for reference in cell.references() {
            let idx = hash_to_index
                .get(&reference.hash())
                .ok_or_else(|| CellError::InvalidBoc("Reference not found".to_string()))?;
            Self::write_uint(&mut result, *idx as u64, ref_size);
        }

        Ok(result)
    }

    /// Parse cells from serialized data.
    fn parse_cells(
        data: &[u8],
        cell_count: usize,
        size_bytes: usize,
    ) -> CellResult<Vec<Arc<Cell>>> {
        let mut cells: Vec<Option<Arc<Cell>>> = vec![None; cell_count];
        let mut offset = 0;

        // First pass: parse cell data and references
        let mut cell_infos: Vec<(Vec<u8>, usize, CellType, Vec<usize>)> = Vec::with_capacity(cell_count);

        for _ in 0..cell_count {
            if offset + 2 > data.len() {
                return Err(CellError::UnexpectedEof);
            }

            let d1 = data[offset];
            let d2 = data[offset + 1];
            offset += 2;

            let refs_count = (d1 & 0x07) as usize;
            let is_exotic = (d1 & 0x08) != 0;
            let _level_mask = d1 >> 5;

            // Calculate data length from d2 first to read exotic type byte
            // d2 = ceil(bit_len / 8) + floor(bit_len / 8)
            // If d2 is even: bit_len = d2 * 4 (byte-aligned)
            // If d2 is odd: bit_len is not byte-aligned
            let data_len = (d2 as usize).div_ceil(2);

            // Determine cell type by reading first byte for exotic cells
            let cell_type = if is_exotic {
                if offset + data_len == 0 || offset >= data.len() {
                    return Err(CellError::InvalidBoc(
                        "Exotic cell has no data to determine type".to_string(),
                    ));
                }
                match data.get(offset) {
                    Some(1) => CellType::PrunedBranch,
                    Some(2) => CellType::Library,
                    Some(3) => CellType::MerkleProof,
                    Some(4) => CellType::MerkleUpdate,
                    Some(t) => {
                        return Err(CellError::InvalidBoc(format!(
                            "Unknown exotic cell type: {}",
                            t
                        )))
                    }
                    None => {
                        return Err(CellError::InvalidBoc(
                            "Cannot read exotic cell type byte".to_string(),
                        ))
                    }
                }
            } else {
                CellType::Ordinary
            };

            let bit_len = if d2.is_multiple_of(2) {
                data_len * 8
            } else {
                // Need to find the completion tag
                data_len * 8 // We'll adjust this after reading the data
            };

            if offset + data_len > data.len() {
                return Err(CellError::UnexpectedEof);
            }

            let cell_data = data[offset..offset + data_len].to_vec();
            offset += data_len;

            // Parse references
            let mut ref_indices = Vec::with_capacity(refs_count);
            for _ in 0..refs_count {
                let ref_idx = Self::read_uint(data, &mut offset, size_bytes)? as usize;
                ref_indices.push(ref_idx);
            }

            // Calculate actual bit_len by finding completion tag
            let actual_bit_len = if !d2.is_multiple_of(2) && !cell_data.is_empty() {
                Self::find_bit_len(&cell_data)
            } else {
                bit_len
            };

            cell_infos.push((cell_data, actual_bit_len, cell_type, ref_indices));
        }

        // Determine iteration order based on reference directions
        // If first cell with refs points to higher indices: iterate forward
        // If first cell with refs points to lower indices: iterate reverse
        let refs_point_higher = cell_infos.iter().enumerate().find_map(|(i, (_, _, _, refs))| {
            if refs.is_empty() {
                None
            } else {
                Some(refs.iter().all(|&r| r > i))
            }
        }).unwrap_or(false);

        let iteration_order: Vec<usize> = if refs_point_higher {
            // Children have higher indices - iterate reverse (parent-first format)
            (0..cell_count).rev().collect()
        } else {
            // Children have lower indices - iterate forward (children-first format)
            (0..cell_count).collect()
        };

        // Second pass: build cells in the determined order
        for i in iteration_order {
            let (data, bit_len, cell_type, ref_indices) = &cell_infos[i];

            // Remove completion tag from data
            let clean_data = Self::remove_completion_tag(data, *bit_len);

            // Get references (they should already be built based on iteration order)
            let references: Vec<Arc<Cell>> = ref_indices
                .iter()
                .map(|&idx| {
                    cells[idx]
                        .clone()
                        .ok_or(CellError::CellNotFound(idx))
                })
                .collect::<CellResult<Vec<_>>>()?;

            cells[i] = Some(Arc::new(Cell::new(
                clean_data,
                *bit_len,
                references,
                *cell_type,
            )));
        }

        // Convert to Vec<Arc<Cell>>
        cells
            .into_iter()
            .enumerate()
            .map(|(i, c)| c.ok_or(CellError::CellNotFound(i)))
            .collect()
    }

    /// Find the actual bit length by looking for completion tag.
    ///
    /// The completion tag is a '1' bit followed by zeros to pad to byte boundary.
    /// We need to find this tag by searching from the end of the data.
    fn find_bit_len(data: &[u8]) -> usize {
        if data.is_empty() {
            return 0;
        }

        // Search backwards for the first non-zero byte containing the completion tag
        for i in (0..data.len()).rev() {
            let byte = data[i];
            if byte != 0 {
                // Found a non-zero byte - the completion tag is the lowest set bit
                let trailing_zeros = byte.trailing_zeros() as usize;
                // Bit length = (byte position + 1) * 8 - trailing zeros - 1 (for the tag itself)
                return (i + 1) * 8 - trailing_zeros - 1;
            }
        }

        // All zeros - empty cell
        0
    }

    /// Remove completion tag from data.
    fn remove_completion_tag(data: &[u8], bit_len: usize) -> Vec<u8> {
        if data.is_empty() || bit_len == 0 {
            return Vec::new();
        }

        let byte_len = bit_len.div_ceil(8);
        let mut result = data[..byte_len].to_vec();

        // Clear bits after bit_len
        let remainder = bit_len % 8;
        if remainder != 0 && !result.is_empty() {
            let mask = !((1u8 << (8 - remainder)) - 1);
            if let Some(last) = result.last_mut() {
                *last &= mask;
            }
        }

        result
    }

    /// Calculate bytes needed to represent a number.
    fn bytes_needed(n: usize) -> usize {
        if n == 0 {
            1
        } else {
            ((64 - (n as u64).leading_zeros()) + 7) as usize / 8
        }
    }

    /// Write an unsigned integer with specified byte width.
    fn write_uint(buf: &mut Vec<u8>, value: u64, bytes: usize) {
        for i in (0..bytes).rev() {
            buf.push((value >> (i * 8)) as u8);
        }
    }

    /// Read an unsigned integer with specified byte width.
    fn read_uint(data: &[u8], offset: &mut usize, bytes: usize) -> CellResult<u64> {
        if *offset + bytes > data.len() {
            return Err(CellError::UnexpectedEof);
        }

        let mut result: u64 = 0;
        for i in 0..bytes {
            result = (result << 8) | (data[*offset + i] as u64);
        }
        *offset += bytes;
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CellBuilder;

    #[test]
    fn test_empty_cell_boc() {
        let cell = CellBuilder::new().build().unwrap();
        let boc = BagOfCells::from_root(cell);

        let serialized = boc.serialize().unwrap();
        let deserialized = BagOfCells::deserialize(&serialized).unwrap();

        assert_eq!(deserialized.root_count(), 1);
        let root = deserialized.single_root().unwrap();
        assert_eq!(root.bit_len(), 0);
        assert_eq!(root.reference_count(), 0);
    }

    #[test]
    fn test_simple_cell_boc() {
        let mut builder = CellBuilder::new();
        builder.store_u32(0xDEADBEEF).unwrap();
        let cell = builder.build().unwrap();
        let original_hash = cell.hash();

        let boc = BagOfCells::from_root(cell);
        let serialized = boc.serialize().unwrap();
        let deserialized = BagOfCells::deserialize(&serialized).unwrap();

        let root = deserialized.single_root().unwrap();
        assert_eq!(root.hash(), original_hash);
    }

    #[test]
    fn test_cell_with_refs_boc() {
        // Create child cells
        let mut child1_builder = CellBuilder::new();
        child1_builder.store_u32(0x11111111).unwrap();
        let child1 = Arc::new(child1_builder.build().unwrap());

        let mut child2_builder = CellBuilder::new();
        child2_builder.store_u32(0x22222222).unwrap();
        let child2 = Arc::new(child2_builder.build().unwrap());

        // Create parent cell
        let mut parent_builder = CellBuilder::new();
        parent_builder.store_u32(0xCAFEBABE).unwrap();
        parent_builder.store_ref(child1.clone()).unwrap();
        parent_builder.store_ref(child2.clone()).unwrap();
        let parent = parent_builder.build().unwrap();
        let original_hash = parent.hash();

        let boc = BagOfCells::from_root(parent);
        let serialized = boc.serialize().unwrap();
        let deserialized = BagOfCells::deserialize(&serialized).unwrap();

        let root = deserialized.single_root().unwrap();
        assert_eq!(root.hash(), original_hash);
        assert_eq!(root.reference_count(), 2);
    }

    #[test]
    fn test_base64_roundtrip() {
        let mut builder = CellBuilder::new();
        builder.store_bytes(&[1, 2, 3, 4, 5, 6, 7, 8]).unwrap();
        let cell = builder.build().unwrap();
        let original_hash = cell.hash();

        let boc = BagOfCells::from_root(cell);
        let base64 = boc.serialize_to_base64().unwrap();

        let deserialized = BagOfCells::deserialize_from_base64(&base64).unwrap();
        let root = deserialized.single_root().unwrap();
        assert_eq!(root.hash(), original_hash);
    }

    #[test]
    fn test_bytes_needed() {
        assert_eq!(BagOfCells::bytes_needed(0), 1);
        assert_eq!(BagOfCells::bytes_needed(1), 1);
        assert_eq!(BagOfCells::bytes_needed(255), 1);
        assert_eq!(BagOfCells::bytes_needed(256), 2);
        assert_eq!(BagOfCells::bytes_needed(65535), 2);
        assert_eq!(BagOfCells::bytes_needed(65536), 3);
    }
}
