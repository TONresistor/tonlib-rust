//! Chunk management for TON Storage.
//!
//! This module handles splitting data into chunks and reassembling them.
//! Each chunk is a fixed-size block of data (default 128 KB) that can be
//! independently verified using Merkle proofs.

use crate::bag::DEFAULT_CHUNK_SIZE;
use crate::error::{StorageError, StorageResult};
use ton_crypto::sha256;

/// A chunk of data from a storage bag.
#[derive(Debug, Clone)]
pub struct Chunk {
    /// Index of this chunk (0-based).
    pub index: usize,
    /// The chunk data.
    pub data: Vec<u8>,
    /// SHA256 hash of the chunk data.
    pub hash: [u8; 32],
}

impl Chunk {
    /// Create a new chunk from data.
    pub fn new(index: usize, data: Vec<u8>) -> Self {
        let hash = sha256(&data);
        Self { index, data, hash }
    }

    /// Create a chunk from data with a precomputed hash.
    pub fn with_hash(index: usize, data: Vec<u8>, hash: [u8; 32]) -> Self {
        Self { index, data, hash }
    }

    /// Verify that the chunk hash is correct.
    pub fn verify_hash(&self) -> bool {
        sha256(&self.data) == self.hash
    }

    /// Get the size of this chunk in bytes.
    pub fn size(&self) -> usize {
        self.data.len()
    }
}

/// Iterator over chunks of data.
pub struct ChunkIterator<'a> {
    data: &'a [u8],
    chunk_size: usize,
    current_index: usize,
}

impl<'a> ChunkIterator<'a> {
    /// Create a new chunk iterator with the default chunk size.
    pub fn new(data: &'a [u8]) -> Self {
        Self::with_chunk_size(data, DEFAULT_CHUNK_SIZE)
    }

    /// Create a new chunk iterator with a custom chunk size.
    pub fn with_chunk_size(data: &'a [u8], chunk_size: usize) -> Self {
        Self {
            data,
            chunk_size,
            current_index: 0,
        }
    }

    /// Get the total number of chunks.
    pub fn count_total(&self) -> usize {
        if self.data.is_empty() {
            return 0;
        }
        self.data.len().div_ceil(self.chunk_size)
    }
}

impl<'a> Iterator for ChunkIterator<'a> {
    type Item = Chunk;

    fn next(&mut self) -> Option<Self::Item> {
        let start = self.current_index * self.chunk_size;
        if start >= self.data.len() {
            return None;
        }

        let end = std::cmp::min(start + self.chunk_size, self.data.len());
        let chunk_data = self.data[start..end].to_vec();
        let chunk = Chunk::new(self.current_index, chunk_data);

        self.current_index += 1;
        Some(chunk)
    }
}

/// Split data into chunks of the specified size.
///
/// # Arguments
/// * `data` - The data to split
/// * `chunk_size` - Size of each chunk (last chunk may be smaller)
///
/// # Returns
/// A vector of chunks
pub fn split_into_chunks(data: &[u8], chunk_size: usize) -> StorageResult<Vec<Chunk>> {
    if chunk_size == 0 {
        return Err(StorageError::InvalidChunkSize(0));
    }

    let chunks: Vec<Chunk> = ChunkIterator::with_chunk_size(data, chunk_size).collect();
    Ok(chunks)
}

/// Reassemble chunks into complete data.
///
/// # Arguments
/// * `chunks` - The chunks to reassemble (must be sorted by index)
/// * `expected_size` - Expected total size of the data
///
/// # Returns
/// The reassembled data
pub fn reassemble_chunks(chunks: &[Chunk], expected_size: u64) -> StorageResult<Vec<u8>> {
    if chunks.is_empty() {
        if expected_size == 0 {
            return Ok(Vec::new());
        }
        return Err(StorageError::EmptyData);
    }

    // Verify chunks are in order
    for (i, chunk) in chunks.iter().enumerate() {
        if chunk.index != i {
            return Err(StorageError::InvalidMerkleProof(format!(
                "Chunk {} has wrong index {}",
                i, chunk.index
            )));
        }
    }

    let mut data = Vec::with_capacity(expected_size as usize);
    for chunk in chunks {
        data.extend_from_slice(&chunk.data);
    }

    if data.len() != expected_size as usize {
        return Err(StorageError::InvalidTorrentInfo(format!(
            "Reassembled size {} doesn't match expected {}",
            data.len(),
            expected_size
        )));
    }

    Ok(data)
}

/// Calculate hashes for all chunks in data.
///
/// # Arguments
/// * `data` - The data to hash
/// * `chunk_size` - Size of each chunk
///
/// # Returns
/// Vector of SHA256 hashes for each chunk
pub fn calculate_chunk_hashes(data: &[u8], chunk_size: usize) -> StorageResult<Vec<[u8; 32]>> {
    if chunk_size == 0 {
        return Err(StorageError::InvalidChunkSize(0));
    }

    let hashes: Vec<[u8; 32]> = data
        .chunks(chunk_size)
        .map(sha256)
        .collect();

    Ok(hashes)
}

/// Get the byte range for a specific chunk.
///
/// # Arguments
/// * `chunk_index` - Index of the chunk
/// * `chunk_size` - Size of each chunk
/// * `total_size` - Total size of the data
///
/// # Returns
/// A tuple of (start_offset, end_offset) for the chunk
pub fn chunk_byte_range(
    chunk_index: usize,
    chunk_size: usize,
    total_size: u64,
) -> StorageResult<(u64, u64)> {
    if chunk_size == 0 {
        return Err(StorageError::InvalidChunkSize(0));
    }

    let total_chunks = (total_size as usize).div_ceil(chunk_size);
    if chunk_index >= total_chunks {
        return Err(StorageError::ChunkIndexOutOfBounds {
            index: chunk_index,
            total: total_chunks,
        });
    }

    let start = (chunk_index * chunk_size) as u64;
    let end = std::cmp::min(start + chunk_size as u64, total_size);

    Ok((start, end))
}

/// Calculate how many chunks are needed for given data size.
pub fn chunk_count(data_size: u64, chunk_size: usize) -> usize {
    if data_size == 0 || chunk_size == 0 {
        return 0;
    }
    (data_size as usize).div_ceil(chunk_size)
}

/// Verify a single chunk against an expected hash.
pub fn verify_chunk_hash(chunk_data: &[u8], expected_hash: &[u8; 32]) -> bool {
    sha256(chunk_data) == *expected_hash
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chunk_creation() {
        let data = vec![1, 2, 3, 4, 5];
        let chunk = Chunk::new(0, data.clone());

        assert_eq!(chunk.index, 0);
        assert_eq!(chunk.data, data);
        assert_eq!(chunk.hash, sha256(&data));
        assert!(chunk.verify_hash());
    }

    #[test]
    fn test_chunk_with_hash() {
        let data = vec![1, 2, 3, 4, 5];
        let hash = sha256(&data);
        let chunk = Chunk::with_hash(0, data.clone(), hash);

        assert!(chunk.verify_hash());

        // Wrong hash should fail verification
        let wrong_hash = [0u8; 32];
        let bad_chunk = Chunk::with_hash(0, data, wrong_hash);
        assert!(!bad_chunk.verify_hash());
    }

    #[test]
    fn test_chunk_iterator() {
        let data = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        let iter = ChunkIterator::with_chunk_size(&data, 3);

        assert_eq!(iter.count_total(), 4); // 10/3 = 3.33, rounded up = 4

        let chunks: Vec<Chunk> = ChunkIterator::with_chunk_size(&data, 3).collect();
        assert_eq!(chunks.len(), 4);
        assert_eq!(chunks[0].data, vec![1, 2, 3]);
        assert_eq!(chunks[1].data, vec![4, 5, 6]);
        assert_eq!(chunks[2].data, vec![7, 8, 9]);
        assert_eq!(chunks[3].data, vec![10]); // Last chunk is smaller
    }

    #[test]
    fn test_chunk_iterator_empty() {
        let data: Vec<u8> = vec![];
        let iter = ChunkIterator::new(&data);
        assert_eq!(iter.count_total(), 0);

        let chunks: Vec<Chunk> = ChunkIterator::new(&data).collect();
        assert!(chunks.is_empty());
    }

    #[test]
    fn test_split_into_chunks() {
        let data = vec![0u8; 100];
        let chunks = split_into_chunks(&data, 30).unwrap();

        assert_eq!(chunks.len(), 4);
        assert_eq!(chunks[0].size(), 30);
        assert_eq!(chunks[1].size(), 30);
        assert_eq!(chunks[2].size(), 30);
        assert_eq!(chunks[3].size(), 10); // Last chunk is 100 - 90 = 10
    }

    #[test]
    fn test_split_into_chunks_zero_size() {
        let data = vec![0u8; 100];
        let result = split_into_chunks(&data, 0);
        assert!(result.is_err());
    }

    #[test]
    fn test_reassemble_chunks() {
        let original = vec![1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        let chunks = split_into_chunks(&original, 3).unwrap();
        let reassembled = reassemble_chunks(&chunks, 10).unwrap();

        assert_eq!(reassembled, original);
    }

    #[test]
    fn test_reassemble_chunks_wrong_size() {
        let original = vec![1u8, 2, 3, 4, 5];
        let chunks = split_into_chunks(&original, 2).unwrap();

        // Wrong expected size
        let result = reassemble_chunks(&chunks, 10);
        assert!(result.is_err());
    }

    #[test]
    fn test_reassemble_empty_chunks() {
        let chunks: Vec<Chunk> = vec![];

        // Empty with expected size 0 is OK
        let result = reassemble_chunks(&chunks, 0).unwrap();
        assert!(result.is_empty());

        // Empty with expected size > 0 is error
        let result = reassemble_chunks(&chunks, 10);
        assert!(result.is_err());
    }

    #[test]
    fn test_calculate_chunk_hashes() {
        let data = vec![1, 2, 3, 4, 5, 6];
        let hashes = calculate_chunk_hashes(&data, 2).unwrap();

        assert_eq!(hashes.len(), 3);
        assert_eq!(hashes[0], sha256(&[1, 2]));
        assert_eq!(hashes[1], sha256(&[3, 4]));
        assert_eq!(hashes[2], sha256(&[5, 6]));
    }

    #[test]
    fn test_chunk_byte_range() {
        let total_size = 100u64;
        let chunk_size = 30;

        let (start, end) = chunk_byte_range(0, chunk_size, total_size).unwrap();
        assert_eq!((start, end), (0, 30));

        let (start, end) = chunk_byte_range(1, chunk_size, total_size).unwrap();
        assert_eq!((start, end), (30, 60));

        let (start, end) = chunk_byte_range(3, chunk_size, total_size).unwrap();
        assert_eq!((start, end), (90, 100)); // Last chunk ends at total_size

        // Out of bounds
        let result = chunk_byte_range(4, chunk_size, total_size);
        assert!(result.is_err());
    }

    #[test]
    fn test_chunk_count() {
        assert_eq!(chunk_count(100, 30), 4);
        assert_eq!(chunk_count(90, 30), 3);
        assert_eq!(chunk_count(0, 30), 0);
        assert_eq!(chunk_count(100, 0), 0);
        assert_eq!(chunk_count(DEFAULT_CHUNK_SIZE as u64 * 8, DEFAULT_CHUNK_SIZE), 8);
    }

    #[test]
    fn test_verify_chunk_hash() {
        let data = vec![1, 2, 3, 4, 5];
        let hash = sha256(&data);

        assert!(verify_chunk_hash(&data, &hash));
        assert!(!verify_chunk_hash(&data, &[0u8; 32]));
    }

    #[test]
    fn test_large_chunk_operations() {
        // Test with default chunk size
        let data: Vec<u8> = (0..DEFAULT_CHUNK_SIZE * 3 + 1000)
            .map(|i| (i % 256) as u8)
            .collect();

        let chunks = split_into_chunks(&data, DEFAULT_CHUNK_SIZE).unwrap();
        assert_eq!(chunks.len(), 4);

        // Verify all chunks
        for chunk in &chunks {
            assert!(chunk.verify_hash());
        }

        // Reassemble and verify
        let reassembled = reassemble_chunks(&chunks, data.len() as u64).unwrap();
        assert_eq!(reassembled, data);
    }
}
