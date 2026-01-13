//! Bag, BagID, TorrentInfo, and TorrentHeader structures for TON Storage.
//!
//! A Bag is a collection of files (similar to a torrent) that can be distributed
//! via the TON Storage network. Each Bag is identified by a BagID, which is the
//! Cell representation hash of the TorrentInfo cell (per official TON).

use crate::error::{StorageError, StorageResult};
use ton_cell::CellBuilder;
use ton_crypto::sha256;

/// Default piece size: 128 KB = 131,072 bytes.
/// This matches the official TON storage implementation (ton-blockchain/storage).
pub const DEFAULT_CHUNK_SIZE: usize = 128 * 1024; // 131072 bytes (128 KB)

/// A 32-byte identifier for a Bag, derived from the TorrentInfo hash.
pub type BagId = [u8; 32];

/// Torrent information describing a Bag of files.
///
/// This structure contains the essential metadata about a torrent:
/// - The chunk size used for splitting data
/// - Total file size
/// - Merkle root hash for verification
/// - Header information for multi-file torrents
#[derive(Debug, Clone)]
pub struct TorrentInfo {
    /// Size of each chunk in bytes (default: 128 KB = 131072).
    pub chunk_size: u32,
    /// Total size of all files in bytes.
    pub file_size: u64,
    /// Root hash of the Merkle tree over all chunks.
    pub root_hash: [u8; 32],
    /// Size of the torrent header in bytes.
    pub header_size: u64,
    /// SHA256 hash of the torrent header.
    pub header_hash: [u8; 32],
    /// Optional description of the torrent.
    pub description: String,
}

impl TorrentInfo {
    /// Create a new TorrentInfo with the given parameters.
    pub fn new(
        file_size: u64,
        root_hash: [u8; 32],
        header_size: u64,
        header_hash: [u8; 32],
    ) -> Self {
        Self {
            chunk_size: DEFAULT_CHUNK_SIZE as u32,
            file_size,
            root_hash,
            header_size,
            header_hash,
            description: String::new(),
        }
    }

    /// Create TorrentInfo with a custom chunk size.
    pub fn with_chunk_size(mut self, chunk_size: u32) -> StorageResult<Self> {
        if chunk_size == 0 {
            return Err(StorageError::InvalidChunkSize(0));
        }
        self.chunk_size = chunk_size;
        Ok(self)
    }

    /// Set the description.
    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.description = description.into();
        self
    }

    /// Calculate the number of chunks needed for this torrent.
    pub fn chunk_count(&self) -> usize {
        if self.file_size == 0 {
            return 0;
        }
        (self.file_size as usize).div_ceil(self.chunk_size as usize)
    }

    /// Calculate the BagID (hash of this TorrentInfo).
    ///
    /// According to official TON Storage, the BagID is computed as the
    /// Cell representation hash of the TorrentInfo Cell, not SHA256 of binary.
    /// This ensures compatibility with TON's proof and verification system.
    pub fn calculate_bag_id(&self) -> BagId {
        // Build a Cell containing the TorrentInfo data
        let mut builder = CellBuilder::new();

        // Store chunk_size (32 bits)
        if builder.store_u32(self.chunk_size).is_err() {
            return self.calculate_bag_id_fallback();
        }

        // Store file_size (64 bits)
        if builder.store_u64(self.file_size).is_err() {
            return self.calculate_bag_id_fallback();
        }

        // Store root_hash (256 bits)
        if builder.store_bytes(&self.root_hash).is_err() {
            return self.calculate_bag_id_fallback();
        }

        // Store header_size (64 bits)
        if builder.store_u64(self.header_size).is_err() {
            return self.calculate_bag_id_fallback();
        }

        // Store header_hash (256 bits)
        if builder.store_bytes(&self.header_hash).is_err() {
            return self.calculate_bag_id_fallback();
        }

        // Build the Cell and return its hash
        match builder.build() {
            Ok(cell) => cell.hash(),
            Err(_) => self.calculate_bag_id_fallback(),
        }
    }

    /// Fallback BagID calculation using SHA256 of binary serialization.
    /// Used when Cell building fails (should not happen in normal operation).
    fn calculate_bag_id_fallback(&self) -> BagId {
        let mut data = Vec::new();
        data.extend_from_slice(&self.chunk_size.to_be_bytes());
        data.extend_from_slice(&self.file_size.to_be_bytes());
        data.extend_from_slice(&self.root_hash);
        data.extend_from_slice(&self.header_size.to_be_bytes());
        data.extend_from_slice(&self.header_hash);
        let desc_bytes = self.description.as_bytes();
        data.extend_from_slice(&(desc_bytes.len() as u32).to_be_bytes());
        data.extend_from_slice(desc_bytes);
        sha256(&data)
    }

    /// Serialize the TorrentInfo to bytes (big-endian for TON compatibility).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut data = Vec::new();

        // chunk_size (4 bytes, big-endian)
        data.extend_from_slice(&self.chunk_size.to_be_bytes());

        // file_size (8 bytes, big-endian)
        data.extend_from_slice(&self.file_size.to_be_bytes());

        // root_hash (32 bytes)
        data.extend_from_slice(&self.root_hash);

        // header_size (8 bytes, big-endian)
        data.extend_from_slice(&self.header_size.to_be_bytes());

        // header_hash (32 bytes)
        data.extend_from_slice(&self.header_hash);

        // description length + data (big-endian)
        let desc_bytes = self.description.as_bytes();
        data.extend_from_slice(&(desc_bytes.len() as u32).to_be_bytes());
        data.extend_from_slice(desc_bytes);

        data
    }

    /// Deserialize TorrentInfo from bytes (big-endian for TON compatibility).
    pub fn from_bytes(data: &[u8]) -> StorageResult<Self> {
        if data.len() < 84 {
            // Minimum: 4 + 8 + 32 + 8 + 32 = 84 bytes
            return Err(StorageError::InvalidTorrentInfo(
                "Data too short".to_string(),
            ));
        }

        let mut offset = 0;

        // chunk_size (4 bytes, big-endian)
        let chunk_size = u32::from_be_bytes(
            data[offset..offset + 4]
                .try_into()
                .map_err(|_| StorageError::InvalidTorrentInfo("Invalid chunk_size".to_string()))?,
        );
        offset += 4;

        // file_size (8 bytes, big-endian)
        let file_size = u64::from_be_bytes(
            data[offset..offset + 8]
                .try_into()
                .map_err(|_| StorageError::InvalidTorrentInfo("Invalid file_size".to_string()))?,
        );
        offset += 8;

        // root_hash (32 bytes)
        let root_hash: [u8; 32] = data[offset..offset + 32]
            .try_into()
            .map_err(|_| StorageError::InvalidTorrentInfo("Invalid root_hash".to_string()))?;
        offset += 32;

        // header_size (8 bytes, big-endian)
        let header_size = u64::from_be_bytes(
            data[offset..offset + 8]
                .try_into()
                .map_err(|_| StorageError::InvalidTorrentInfo("Invalid header_size".to_string()))?,
        );
        offset += 8;

        // header_hash (32 bytes)
        let header_hash: [u8; 32] = data[offset..offset + 32]
            .try_into()
            .map_err(|_| StorageError::InvalidTorrentInfo("Invalid header_hash".to_string()))?;
        offset += 32;

        // description
        let description = if offset + 4 <= data.len() {
            let desc_len = u32::from_be_bytes(
                data[offset..offset + 4].try_into().map_err(|_| {
                    StorageError::InvalidTorrentInfo("Invalid description length".to_string())
                })?,
            ) as usize;
            offset += 4;

            if offset + desc_len <= data.len() {
                String::from_utf8(data[offset..offset + desc_len].to_vec()).map_err(|_| {
                    StorageError::InvalidTorrentInfo("Invalid description encoding".to_string())
                })?
            } else {
                String::new()
            }
        } else {
            String::new()
        };

        Ok(Self {
            chunk_size,
            file_size,
            root_hash,
            header_size,
            header_hash,
            description,
        })
    }
}

/// Torrent header containing file structure information.
///
/// For multi-file torrents, the header describes how files are
/// arranged within the concatenated data.
#[derive(Debug, Clone)]
pub struct TorrentHeader {
    /// Number of files in the torrent.
    pub files_count: u32,
    /// Offsets to filenames within the name data.
    pub name_index: Vec<u64>,
    /// Offsets to file data within the torrent data.
    pub data_index: Vec<u64>,
    /// File names (relative paths).
    pub names: Vec<String>,
}

impl TorrentHeader {
    /// Create a new empty TorrentHeader.
    pub fn new() -> Self {
        Self {
            files_count: 0,
            name_index: Vec::new(),
            data_index: Vec::new(),
            names: Vec::new(),
        }
    }

    /// Create a TorrentHeader for a single file.
    pub fn single_file(name: impl Into<String>, size: u64) -> Self {
        Self {
            files_count: 1,
            name_index: vec![0],
            data_index: vec![size],
            names: vec![name.into()],
        }
    }

    /// Add a file to the header.
    pub fn add_file(&mut self, name: impl Into<String>, size: u64) {
        let name_offset = self
            .names
            .iter()
            .map(|n| n.len() as u64)
            .sum::<u64>();
        let data_offset = self.data_index.last().copied().unwrap_or(0);

        self.name_index.push(name_offset);
        self.data_index.push(data_offset + size);
        self.names.push(name.into());
        self.files_count += 1;
    }

    /// Get file information by name.
    ///
    /// Returns `(offset, size)` where offset is the byte position in the
    /// concatenated data and size is the file size in bytes.
    pub fn get_file(&self, name: &str) -> Option<(u64, u64)> {
        for (i, n) in self.names.iter().enumerate() {
            if n == name {
                // data_index stores cumulative end positions
                // So file i starts at data_index[i-1] (or 0 for first file)
                // and ends at data_index[i]
                let start = if i == 0 { 0 } else { self.data_index[i - 1] };
                let end = self.data_index[i];
                return Some((start, end - start));
            }
        }
        None
    }

    /// Calculate the SHA256 hash of the header.
    pub fn calculate_hash(&self) -> [u8; 32] {
        sha256(&self.to_bytes())
    }

    /// Serialize the TorrentHeader to bytes (big-endian for TON compatibility).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut data = Vec::new();

        // files_count (4 bytes, big-endian)
        data.extend_from_slice(&self.files_count.to_be_bytes());

        // name_index count and values (big-endian)
        data.extend_from_slice(&(self.name_index.len() as u32).to_be_bytes());
        for &offset in &self.name_index {
            data.extend_from_slice(&offset.to_be_bytes());
        }

        // data_index count and values (big-endian)
        data.extend_from_slice(&(self.data_index.len() as u32).to_be_bytes());
        for &offset in &self.data_index {
            data.extend_from_slice(&offset.to_be_bytes());
        }

        // names count and values (big-endian)
        data.extend_from_slice(&(self.names.len() as u32).to_be_bytes());
        for name in &self.names {
            let name_bytes = name.as_bytes();
            data.extend_from_slice(&(name_bytes.len() as u32).to_be_bytes());
            data.extend_from_slice(name_bytes);
        }

        data
    }

    /// Deserialize TorrentHeader from bytes (big-endian for TON compatibility).
    pub fn from_bytes(data: &[u8]) -> StorageResult<Self> {
        if data.len() < 4 {
            return Err(StorageError::InvalidTorrentHeader(
                "Data too short".to_string(),
            ));
        }

        let mut offset = 0;

        // files_count (4 bytes, big-endian)
        let files_count = u32::from_be_bytes(
            data[offset..offset + 4]
                .try_into()
                .map_err(|_| StorageError::InvalidTorrentHeader("Invalid files_count".to_string()))?,
        );
        offset += 4;

        // name_index
        if offset + 4 > data.len() {
            return Err(StorageError::InvalidTorrentHeader(
                "Truncated name_index count".to_string(),
            ));
        }
        let name_index_count = u32::from_be_bytes(
            data[offset..offset + 4]
                .try_into()
                .map_err(|_| StorageError::InvalidTorrentHeader("Invalid name_index count".to_string()))?,
        ) as usize;
        offset += 4;

        let mut name_index = Vec::with_capacity(name_index_count);
        for _ in 0..name_index_count {
            if offset + 8 > data.len() {
                return Err(StorageError::InvalidTorrentHeader(
                    "Truncated name_index".to_string(),
                ));
            }
            name_index.push(u64::from_be_bytes(
                data[offset..offset + 8].try_into().unwrap(),
            ));
            offset += 8;
        }

        // data_index
        if offset + 4 > data.len() {
            return Err(StorageError::InvalidTorrentHeader(
                "Truncated data_index count".to_string(),
            ));
        }
        let data_index_count = u32::from_be_bytes(
            data[offset..offset + 4]
                .try_into()
                .map_err(|_| StorageError::InvalidTorrentHeader("Invalid data_index count".to_string()))?,
        ) as usize;
        offset += 4;

        let mut data_index = Vec::with_capacity(data_index_count);
        for _ in 0..data_index_count {
            if offset + 8 > data.len() {
                return Err(StorageError::InvalidTorrentHeader(
                    "Truncated data_index".to_string(),
                ));
            }
            data_index.push(u64::from_be_bytes(
                data[offset..offset + 8].try_into().unwrap(),
            ));
            offset += 8;
        }

        // names
        if offset + 4 > data.len() {
            return Err(StorageError::InvalidTorrentHeader(
                "Truncated names count".to_string(),
            ));
        }
        let names_count = u32::from_be_bytes(
            data[offset..offset + 4]
                .try_into()
                .map_err(|_| StorageError::InvalidTorrentHeader("Invalid names count".to_string()))?,
        ) as usize;
        offset += 4;

        let mut names = Vec::with_capacity(names_count);
        for _ in 0..names_count {
            if offset + 4 > data.len() {
                return Err(StorageError::InvalidTorrentHeader(
                    "Truncated name length".to_string(),
                ));
            }
            let name_len = u32::from_be_bytes(
                data[offset..offset + 4].try_into().unwrap(),
            ) as usize;
            offset += 4;

            if offset + name_len > data.len() {
                return Err(StorageError::InvalidTorrentHeader(
                    "Truncated name data".to_string(),
                ));
            }
            let name = String::from_utf8(data[offset..offset + name_len].to_vec())
                .map_err(|_| StorageError::InvalidTorrentHeader("Invalid name encoding".to_string()))?;
            offset += name_len;
            names.push(name);
        }

        Ok(Self {
            files_count,
            name_index,
            data_index,
            names,
        })
    }
}

impl Default for TorrentHeader {
    fn default() -> Self {
        Self::new()
    }
}

/// A complete Bag containing torrent info, header, and data management.
#[derive(Debug, Clone)]
pub struct Bag {
    /// The unique identifier for this bag.
    pub bag_id: BagId,
    /// Torrent metadata.
    pub info: TorrentInfo,
    /// File structure header.
    pub header: TorrentHeader,
}

impl Bag {
    /// Create a new Bag from torrent info and header.
    pub fn new(info: TorrentInfo, header: TorrentHeader) -> Self {
        let bag_id = info.calculate_bag_id();
        Self {
            bag_id,
            info,
            header,
        }
    }

    /// Get the total number of chunks in this bag.
    pub fn chunk_count(&self) -> usize {
        self.info.chunk_count()
    }

    /// Get the size of a specific chunk.
    ///
    /// All chunks except the last one have the full chunk size.
    /// The last chunk may be smaller.
    pub fn chunk_size(&self, chunk_index: usize) -> StorageResult<usize> {
        let total_chunks = self.chunk_count();
        if chunk_index >= total_chunks {
            return Err(StorageError::ChunkIndexOutOfBounds {
                index: chunk_index,
                total: total_chunks,
            });
        }

        let chunk_size = self.info.chunk_size as usize;
        if chunk_index == total_chunks - 1 {
            // Last chunk may be smaller
            let remainder = (self.info.file_size as usize) % chunk_size;
            if remainder == 0 {
                Ok(chunk_size)
            } else {
                Ok(remainder)
            }
        } else {
            Ok(chunk_size)
        }
    }

    /// Get the byte range for a specific chunk.
    pub fn chunk_range(&self, chunk_index: usize) -> StorageResult<(u64, u64)> {
        let total_chunks = self.chunk_count();
        if chunk_index >= total_chunks {
            return Err(StorageError::ChunkIndexOutOfBounds {
                index: chunk_index,
                total: total_chunks,
            });
        }

        let chunk_size = self.info.chunk_size as u64;
        let start = chunk_index as u64 * chunk_size;
        let end = std::cmp::min(start + chunk_size, self.info.file_size);

        Ok((start, end))
    }

    /// Get file info by name.
    pub fn get_file(&self, name: &str) -> StorageResult<(u64, u64)> {
        self.header
            .get_file(name)
            .ok_or_else(|| StorageError::FileNotFound(name.to_string()))
    }
}

/// Calculate the DHT key for finding storage peers for a bag.
///
/// The DHT key is: SHA256("storage" || bag_id)
pub fn dht_key_for_storage(bag_id: &BagId) -> [u8; 32] {
    let mut data = Vec::with_capacity(7 + 32);
    data.extend_from_slice(b"storage");
    data.extend_from_slice(bag_id);
    sha256(&data)
}

/// Calculate the overlay network ID for a storage bag.
///
/// This is used to find peers that are sharing the same bag.
pub fn storage_overlay_id(bag_id: &BagId) -> [u8; 32] {
    let mut data = Vec::with_capacity(15 + 32);
    data.extend_from_slice(b"storage.overlay");
    data.extend_from_slice(bag_id);
    sha256(&data)
}

/// Format a BagId as a hex string.
pub fn bag_id_to_hex(bag_id: &BagId) -> String {
    bag_id.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Parse a BagId from a hex string.
pub fn bag_id_from_hex(hex: &str) -> StorageResult<BagId> {
    if hex.len() != 64 {
        return Err(StorageError::InvalidBagId(format!(
            "Expected 64 hex chars, got {}",
            hex.len()
        )));
    }

    let mut bag_id = [0u8; 32];
    for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
        let hex_str = std::str::from_utf8(chunk)
            .map_err(|_| StorageError::InvalidBagId("Invalid UTF-8".to_string()))?;
        bag_id[i] = u8::from_str_radix(hex_str, 16)
            .map_err(|_| StorageError::InvalidBagId(format!("Invalid hex: {}", hex_str)))?;
    }

    Ok(bag_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_torrent_info_basic() {
        let root_hash = [1u8; 32];
        let header_hash = [2u8; 32];
        let info = TorrentInfo::new(1024 * 1024, root_hash, 100, header_hash);

        assert_eq!(info.chunk_size, DEFAULT_CHUNK_SIZE as u32);
        assert_eq!(info.file_size, 1024 * 1024);
        assert_eq!(info.root_hash, root_hash);
        assert_eq!(info.header_size, 100);
        assert_eq!(info.header_hash, header_hash);
    }

    #[test]
    fn test_torrent_info_chunk_count() {
        let info = TorrentInfo::new(1024 * 1024, [0u8; 32], 0, [0u8; 32]);
        // 1 MB (1,048,576) / 131,072 bytes per chunk = 8 chunks
        // (Using official TON piece_size: 128 KB = 131,072 bytes)
        assert_eq!(info.chunk_count(), 8);

        let info2 = TorrentInfo::new(1024 * 1024 + 1, [0u8; 32], 0, [0u8; 32]);
        // 1 MB + 1 byte needs 9 chunks (8 * 131072 = 1,048,576, so 1 more byte needs 9th chunk)
        assert_eq!(info2.chunk_count(), 9);

        let info3 = TorrentInfo::new(0, [0u8; 32], 0, [0u8; 32]);
        assert_eq!(info3.chunk_count(), 0);

        // Verify exact chunk boundary
        let info4 = TorrentInfo::new(DEFAULT_CHUNK_SIZE as u64 * 10, [0u8; 32], 0, [0u8; 32]);
        assert_eq!(info4.chunk_count(), 10);
    }

    #[test]
    fn test_torrent_info_serialization() {
        let info = TorrentInfo::new(1024 * 1024, [1u8; 32], 100, [2u8; 32])
            .with_description("Test torrent");

        let bytes = info.to_bytes();
        let restored = TorrentInfo::from_bytes(&bytes).unwrap();

        assert_eq!(info.chunk_size, restored.chunk_size);
        assert_eq!(info.file_size, restored.file_size);
        assert_eq!(info.root_hash, restored.root_hash);
        assert_eq!(info.header_size, restored.header_size);
        assert_eq!(info.header_hash, restored.header_hash);
        assert_eq!(info.description, restored.description);
    }

    #[test]
    fn test_bag_id_calculation() {
        let info = TorrentInfo::new(1024, [1u8; 32], 0, [0u8; 32]);
        let bag_id = info.calculate_bag_id();

        // Same info should produce same bag_id
        let info2 = TorrentInfo::new(1024, [1u8; 32], 0, [0u8; 32]);
        let bag_id2 = info2.calculate_bag_id();
        assert_eq!(bag_id, bag_id2);

        // Different info should produce different bag_id
        let info3 = TorrentInfo::new(2048, [1u8; 32], 0, [0u8; 32]);
        let bag_id3 = info3.calculate_bag_id();
        assert_ne!(bag_id, bag_id3);
    }

    #[test]
    fn test_torrent_header_single_file() {
        let header = TorrentHeader::single_file("test.txt", 1024);

        assert_eq!(header.files_count, 1);
        assert_eq!(header.names.len(), 1);
        assert_eq!(header.names[0], "test.txt");

        let (offset, size) = header.get_file("test.txt").unwrap();
        assert_eq!(offset, 0);
        assert_eq!(size, 1024);
    }

    #[test]
    fn test_torrent_header_multi_file() {
        let mut header = TorrentHeader::new();
        header.add_file("file1.txt", 100);
        header.add_file("file2.txt", 200);
        header.add_file("dir/file3.txt", 300);

        assert_eq!(header.files_count, 3);
        assert_eq!(header.names.len(), 3);

        let (offset1, size1) = header.get_file("file1.txt").unwrap();
        assert_eq!(offset1, 0);
        assert_eq!(size1, 100);

        let (offset2, size2) = header.get_file("file2.txt").unwrap();
        assert_eq!(offset2, 100);
        assert_eq!(size2, 200);

        let (offset3, size3) = header.get_file("dir/file3.txt").unwrap();
        assert_eq!(offset3, 300);
        assert_eq!(size3, 300);

        assert!(header.get_file("nonexistent.txt").is_none());
    }

    #[test]
    fn test_torrent_header_serialization() {
        let mut header = TorrentHeader::new();
        header.add_file("file1.txt", 100);
        header.add_file("file2.txt", 200);

        let bytes = header.to_bytes();
        let restored = TorrentHeader::from_bytes(&bytes).unwrap();

        assert_eq!(header.files_count, restored.files_count);
        assert_eq!(header.names, restored.names);
        assert_eq!(header.data_index, restored.data_index);
    }

    #[test]
    fn test_bag_chunk_operations() {
        let info = TorrentInfo::new(
            DEFAULT_CHUNK_SIZE as u64 * 2 + 1000, // 2.something chunks
            [0u8; 32],
            0,
            [0u8; 32],
        );
        let header = TorrentHeader::single_file("data.bin", DEFAULT_CHUNK_SIZE as u64 * 2 + 1000);
        let bag = Bag::new(info, header);

        assert_eq!(bag.chunk_count(), 3);

        // First chunk: full size
        assert_eq!(bag.chunk_size(0).unwrap(), DEFAULT_CHUNK_SIZE);
        let (start, end) = bag.chunk_range(0).unwrap();
        assert_eq!(start, 0);
        assert_eq!(end, DEFAULT_CHUNK_SIZE as u64);

        // Second chunk: full size
        assert_eq!(bag.chunk_size(1).unwrap(), DEFAULT_CHUNK_SIZE);

        // Third (last) chunk: partial
        assert_eq!(bag.chunk_size(2).unwrap(), 1000);

        // Out of bounds
        assert!(bag.chunk_size(3).is_err());
        assert!(bag.chunk_range(3).is_err());
    }

    #[test]
    fn test_bag_get_file() {
        let info = TorrentInfo::new(1024, [0u8; 32], 0, [0u8; 32]);
        let header = TorrentHeader::single_file("test.txt", 1024);
        let bag = Bag::new(info, header);

        let (offset, size) = bag.get_file("test.txt").unwrap();
        assert_eq!(offset, 0);
        assert_eq!(size, 1024);

        assert!(bag.get_file("missing.txt").is_err());
    }

    #[test]
    fn test_dht_key_for_storage() {
        let bag_id = [1u8; 32];
        let key = dht_key_for_storage(&bag_id);

        // Key should be deterministic
        let key2 = dht_key_for_storage(&bag_id);
        assert_eq!(key, key2);

        // Different bag_id should give different key
        let bag_id2 = [2u8; 32];
        let key3 = dht_key_for_storage(&bag_id2);
        assert_ne!(key, key3);
    }

    #[test]
    fn test_storage_overlay_id() {
        let bag_id = [1u8; 32];
        let overlay_id = storage_overlay_id(&bag_id);

        // Should be deterministic
        let overlay_id2 = storage_overlay_id(&bag_id);
        assert_eq!(overlay_id, overlay_id2);

        // Different from DHT key
        let dht_key = dht_key_for_storage(&bag_id);
        assert_ne!(overlay_id, dht_key);
    }

    #[test]
    fn test_bag_id_hex_conversion() {
        let bag_id = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab,
            0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67,
            0x89, 0xab, 0xcd, 0xef,
        ];

        let hex = bag_id_to_hex(&bag_id);
        assert_eq!(hex.len(), 64);
        assert_eq!(
            hex,
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        );

        let restored = bag_id_from_hex(&hex).unwrap();
        assert_eq!(bag_id, restored);
    }

    #[test]
    fn test_bag_id_from_hex_invalid() {
        // Too short
        assert!(bag_id_from_hex("0123").is_err());

        // Invalid hex
        assert!(bag_id_from_hex(
            "xyz3456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        )
        .is_err());
    }

    #[test]
    fn test_custom_chunk_size() {
        let info = TorrentInfo::new(1024, [0u8; 32], 0, [0u8; 32])
            .with_chunk_size(256)
            .unwrap();
        assert_eq!(info.chunk_size, 256);
        assert_eq!(info.chunk_count(), 4);

        // Zero chunk size should fail
        let result = TorrentInfo::new(1024, [0u8; 32], 0, [0u8; 32]).with_chunk_size(0);
        assert!(result.is_err());
    }
}
