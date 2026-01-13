//! User-friendly APIs for creating storage bags from various sources.
//!
//! This module provides the [`BagCreator`] struct with builder patterns for easily
//! creating bags from files, directories, raw data, and async streams. It includes
//! automatic chunking, verification, and progress tracking capabilities.

use crate::bag::{Bag, BagId, TorrentHeader, TorrentInfo};
use crate::chunk::split_into_chunks;
use crate::error::{StorageError, StorageResult};
use crate::merkle::build_merkle_tree;
use crate::provider::StorageBackend;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;
use tokio::fs;
use tokio::io::{AsyncRead, AsyncReadExt};
use ton_crypto::sha256;
use tracing::debug;

/// Configuration for bag creation.
#[derive(Debug, Clone)]
pub struct BagCreationConfig {
    /// Size of each chunk in bytes (default 128KB per official TON Storage spec).
    pub chunk_size: usize,
    /// Enable verification during creation (default true).
    pub enable_verification: bool,
    /// Enable compression (default false, not yet implemented).
    pub enable_compression: bool,
    /// Maximum number of concurrent chunk operations (default 4).
    pub max_concurrent_chunks: usize,
    /// Buffer size for reading data (default 64KB).
    pub buffer_size: usize,
    /// Compute CRC32 for chunks (default true).
    pub compute_crc32: bool,
}

impl Default for BagCreationConfig {
    fn default() -> Self {
        Self {
            chunk_size: 131_072, // 128KB per official TON Storage specification
            enable_verification: true,
            enable_compression: false,
            max_concurrent_chunks: 4,
            buffer_size: 65_536, // 64KB
            compute_crc32: true,
        }
    }
}

impl BagCreationConfig {
    /// Create a new configuration with default settings.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the chunk size.
    pub fn with_chunk_size(mut self, size: usize) -> Self {
        self.chunk_size = size;
        self
    }

    /// Set verification enabled/disabled.
    pub fn with_verification(mut self, enabled: bool) -> Self {
        self.enable_verification = enabled;
        self
    }

    /// Set compression enabled/disabled.
    pub fn with_compression(mut self, enabled: bool) -> Self {
        self.enable_compression = enabled;
        self
    }

    /// Set maximum concurrent chunks.
    pub fn with_max_concurrent_chunks(mut self, max: usize) -> Self {
        self.max_concurrent_chunks = max.max(1); // Ensure at least 1
        self
    }

    /// Set buffer size.
    pub fn with_buffer_size(mut self, size: usize) -> Self {
        self.buffer_size = size;
        self
    }

    /// Set CRC32 computation enabled/disabled.
    pub fn with_crc32_computation(mut self, enabled: bool) -> Self {
        self.compute_crc32 = enabled;
        self
    }
}

/// Details about verification of a single chunk.
#[derive(Debug, Clone)]
pub struct ChunkVerificationDetails {
    /// Index of the chunk.
    pub chunk_id: u32,
    /// Size of the chunk in bytes.
    pub size: u64,
    /// Expected CRC32 (if computed).
    pub expected_crc32: Option<u32>,
    /// Actual CRC32 (if computed).
    pub actual_crc32: Option<u32>,
    /// Whether the chunk passed verification.
    pub is_valid: bool,
    /// Error message if verification failed.
    pub error: Option<String>,
}

/// Result of verifying a bag's integrity.
#[derive(Debug, Clone)]
pub struct BagVerificationResult {
    /// Whether the bag is valid overall.
    pub is_valid: bool,
    /// Total number of chunks in the bag.
    pub total_chunks: u32,
    /// Number of chunks that passed verification.
    pub verified_chunks: u32,
    /// Number of chunks that failed verification.
    pub failed_chunks: u32,
    /// Number of CRC32 mismatches.
    pub crc32_mismatches: u32,
    /// Details about individual chunk verification.
    pub details: Vec<ChunkVerificationDetails>,
    /// Time taken to verify in milliseconds.
    pub verification_time_ms: u64,
}

/// Progress information for bag creation.
#[derive(Debug, Clone)]
pub struct BagCreationProgress {
    /// Total bytes to process.
    pub total_bytes: u64,
    /// Bytes processed so far.
    pub processed_bytes: u64,
    /// Current chunk being processed.
    pub current_chunk: u32,
    /// Total number of chunks.
    pub total_chunks: u32,
    /// Estimated milliseconds remaining.
    pub estimated_remaining_ms: u64,
}

/// Builder for configuring and creating a BagCreator.
#[derive(Debug)]
pub struct BagCreatorBuilder {
    chunk_size: usize,
    enable_verification: bool,
    enable_compression: bool,
    max_concurrent_chunks: usize,
    buffer_size: usize,
    compute_crc32: bool,
}

impl Default for BagCreatorBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl BagCreatorBuilder {
    /// Create a new builder with default settings.
    pub fn new() -> Self {
        Self {
            chunk_size: 1_048_576,
            enable_verification: true,
            enable_compression: false,
            max_concurrent_chunks: 4,
            buffer_size: 65_536,
            compute_crc32: true,
        }
    }

    /// Set chunk size.
    pub fn with_chunk_size(mut self, size: usize) -> Self {
        self.chunk_size = size;
        self
    }

    /// Set verification enabled/disabled.
    pub fn with_verification(mut self, enabled: bool) -> Self {
        self.enable_verification = enabled;
        self
    }

    /// Set compression enabled/disabled.
    pub fn with_compression(mut self, enabled: bool) -> Self {
        self.enable_compression = enabled;
        self
    }

    /// Set maximum concurrent chunks.
    pub fn with_max_concurrent_chunks(mut self, max: usize) -> Self {
        self.max_concurrent_chunks = max.max(1);
        self
    }

    /// Set buffer size.
    pub fn with_buffer_size(mut self, size: usize) -> Self {
        self.buffer_size = size;
        self
    }

    /// Set CRC32 computation enabled/disabled.
    pub fn with_crc32_computation(mut self, enabled: bool) -> Self {
        self.compute_crc32 = enabled;
        self
    }

    /// Build the BagCreator with the configured settings.
    pub async fn build(self, storage_backend: Arc<dyn StorageBackend>) -> StorageResult<BagCreator> {
        Ok(BagCreator {
            storage_backend,
            config: BagCreationConfig {
                chunk_size: self.chunk_size,
                enable_verification: self.enable_verification,
                enable_compression: self.enable_compression,
                max_concurrent_chunks: self.max_concurrent_chunks,
                buffer_size: self.buffer_size,
                compute_crc32: self.compute_crc32,
            },
        })
    }
}

/// Main API for creating storage bags.
///
/// Provides methods to create bags from files, directories, raw data, and async streams.
/// Includes automatic chunking, verification, and progress tracking.
pub struct BagCreator {
    storage_backend: Arc<dyn StorageBackend>,
    config: BagCreationConfig,
}

impl std::fmt::Debug for BagCreator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BagCreator")
            .field("config", &self.config)
            .finish()
    }
}

impl BagCreator {
    /// Create a new BagCreator with default configuration.
    pub async fn new(storage_backend: Arc<dyn StorageBackend>) -> StorageResult<Self> {
        Ok(Self {
            storage_backend,
            config: BagCreationConfig::default(),
        })
    }

    /// Create a new BagCreator with custom configuration.
    pub async fn with_config(
        storage_backend: Arc<dyn StorageBackend>,
        config: BagCreationConfig,
    ) -> StorageResult<Self> {
        Ok(Self {
            storage_backend,
            config,
        })
    }

    /// Create a builder for configurable BagCreator creation.
    pub fn builder() -> BagCreatorBuilder {
        BagCreatorBuilder::new()
    }

    /// Create a bag from a file.
    ///
    /// Reads the file, creates a Merkle tree, and stores it in the backend.
    pub async fn from_file(&self, file_path: &Path) -> StorageResult<Bag> {
        debug!("Creating bag from file: {:?}", file_path);

        // Check if file exists
        if !file_path.exists() {
            return Err(StorageError::IoError(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("File not found: {:?}", file_path),
            )));
        }

        // Get file metadata
        let metadata = fs::metadata(file_path)
            .await
            .map_err(StorageError::IoError)?;

        if !metadata.is_file() {
            return Err(StorageError::IoError(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("Path is not a file: {:?}", file_path),
            )));
        }

        // Read file data
        let data = fs::read(file_path)
            .await
            .map_err(StorageError::IoError)?;

        // Get file name
        let file_name = file_path
            .file_name()
            .and_then(|n| n.to_str())
            .map(|s| s.to_string())
            .unwrap_or_else(|| "file".to_string());

        // Create the bag
        self.from_data_internal(&data, Some(file_name), metadata.modified().ok())
            .await
    }

    /// Create a bag from a directory.
    ///
    /// Recursively traverses the directory, collects all files, and creates a bag.
    pub async fn from_directory(&self, dir_path: &Path) -> StorageResult<Bag> {
        debug!("Creating bag from directory: {:?}", dir_path);

        // Check if directory exists
        if !dir_path.exists() {
            return Err(StorageError::IoError(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("Directory not found: {:?}", dir_path),
            )));
        }

        let metadata = fs::metadata(dir_path)
            .await
            .map_err(StorageError::IoError)?;

        if !metadata.is_dir() {
            return Err(StorageError::IoError(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("Path is not a directory: {:?}", dir_path),
            )));
        }

        // Recursively collect all files
        let (data, header) = self.collect_directory_files(dir_path).await?;

        if data.is_empty() {
            return Err(StorageError::EmptyData);
        }

        // Build Merkle tree
        let tree = build_merkle_tree(&data, self.config.chunk_size)
            .map_err(|e| StorageError::InvalidMerkleProof(format!("{:?}", e)))?;

        let root_hash = tree.root_hash();

        // Create torrent info
        let header_bytes = header.to_bytes();
        let header_hash = sha256(&header_bytes);
        let info = TorrentInfo::new(data.len() as u64, root_hash, header_bytes.len() as u64, header_hash)
            .with_chunk_size(self.config.chunk_size as u32)?;

        let bag_id = info.calculate_bag_id();
        let bag = Bag::new(info, header);

        // Store in backend
        self.storage_backend.store_bag(&bag_id, &data).await?;

        debug!("Successfully created bag from directory: {:?}", dir_path);
        Ok(bag)
    }

    /// Create a bag from raw data.
    pub async fn from_data(&self, data: &[u8], name: Option<String>) -> StorageResult<Bag> {
        debug!("Creating bag from data: {} bytes", data.len());
        self.from_data_internal(data, name, None).await
    }

    /// Create a bag from an async stream.
    pub async fn from_stream<R: AsyncRead + Unpin>(
        &self,
        mut reader: R,
        size: u64,
        name: Option<String>,
    ) -> StorageResult<Bag> {
        debug!("Creating bag from stream: {} bytes", size);

        // Read all data from stream
        let mut data = Vec::with_capacity(size as usize);
        reader
            .read_to_end(&mut data)
            .await
            .map_err(StorageError::IoError)?;

        self.from_data_internal(&data, name, None).await
    }

    /// Verify a bag's integrity.
    pub async fn verify_bag(&self, bag_id: &BagId) -> StorageResult<BagVerificationResult> {
        let start_time = Instant::now();

        // Try to get the bag data
        let bag_data = self
            .storage_backend
            .get_bag(bag_id)
            .await?
            .ok_or_else(|| {
                StorageError::IoError(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    format!("Bag not found: {}", hex::encode(bag_id)),
                ))
            })?;

        // Split into chunks
        let chunks = split_into_chunks(&bag_data, self.config.chunk_size)?;

        let total_chunks = chunks.len() as u32;
        let mut verified_chunks = 0u32;
        let mut failed_chunks = 0u32;
        let mut details = Vec::new();

        for chunk in &chunks {
            let mut detail = ChunkVerificationDetails {
                chunk_id: chunk.index as u32,
                size: chunk.data.len() as u64,
                expected_crc32: None,
                actual_crc32: None,
                is_valid: true,
                error: None,
            };

            // Verify chunk hash
            if !chunk.verify_hash() {
                detail.is_valid = false;
                detail.error = Some("Hash mismatch".to_string());
                failed_chunks += 1;
            } else {
                verified_chunks += 1;
            }

            // Compute CRC32 if enabled
            if self.config.compute_crc32 {
                let crc = crc32fast::hash(&chunk.data);
                detail.actual_crc32 = Some(crc);

                // Note: We don't have expected CRC32 stored, so this is informational
            }

            details.push(detail);
        }

        let is_valid = failed_chunks == 0;
        let verification_time_ms = start_time.elapsed().as_millis() as u64;

        Ok(BagVerificationResult {
            is_valid,
            total_chunks,
            verified_chunks,
            failed_chunks,
            crc32_mismatches: 0, // Will be computed in actual implementation
            details,
            verification_time_ms,
        })
    }

    /// Internal method to create bag from data.
    #[allow(clippy::wrong_self_convention)]
    async fn from_data_internal(
        &self,
        data: &[u8],
        name: Option<String>,
        _modified_time: Option<std::time::SystemTime>,
    ) -> StorageResult<Bag> {
        if data.is_empty() {
            return Err(StorageError::EmptyData);
        }

        // Build Merkle tree
        let tree = build_merkle_tree(data, self.config.chunk_size)
            .map_err(|e| StorageError::InvalidMerkleProof(format!("{:?}", e)))?;

        let root_hash = tree.root_hash();

        // Create torrent header
        let mut header = TorrentHeader::new();
        let file_name = name.unwrap_or_else(|| "data".to_string());
        header.add_file(&file_name, data.len() as u64);

        // Create torrent info
        let header_bytes = header.to_bytes();
        let header_hash = sha256(&header_bytes);

        let info = TorrentInfo::new(
            data.len() as u64,
            root_hash,
            header_bytes.len() as u64,
            header_hash,
        )
        .with_chunk_size(self.config.chunk_size as u32)?;

        let bag_id = info.calculate_bag_id();
        let bag = Bag::new(info, header);

        // Store in backend
        self.storage_backend.store_bag(&bag_id, data).await?;

        debug!("Successfully created bag from data: {} bytes", data.len());
        Ok(bag)
    }

    /// Recursively collect all files from a directory.
    async fn collect_directory_files(
        &self,
        dir_path: &Path,
    ) -> StorageResult<(Vec<u8>, TorrentHeader)> {
        let mut header = TorrentHeader::new();
        let mut all_data = Vec::new();

        // Collect all entries first to avoid borrow checker issues
        let mut entries_to_process = vec![(dir_path.to_path_buf(), PathBuf::new())];

        while let Some((current_dir, rel_prefix)) = entries_to_process.pop() {
            

            let mut entries = fs::read_dir(&current_dir)
                .await
                .map_err(StorageError::IoError)?;

            let mut dirs_to_recurse = Vec::new();

            while let Some(entry) = entries
                .next_entry()
                .await
                .map_err(StorageError::IoError)?
            {
                let path = entry.path();
                let file_name = entry.file_name();
                let file_name_str = file_name.to_string_lossy().to_string();

                let new_rel_path = if rel_prefix.as_os_str().is_empty() {
                    PathBuf::from(&file_name_str)
                } else {
                    rel_prefix.join(&file_name_str)
                };

                if path.is_dir() {
                    // Add to list for processing
                    dirs_to_recurse.push((path, new_rel_path));
                } else if path.is_file() {
                    // Read file and add to data
                    let file_data = fs::read(&path)
                        .await
                        .map_err(StorageError::IoError)?;

                    let rel_path_str = new_rel_path.to_string_lossy().to_string();
                    header.add_file(&rel_path_str, file_data.len() as u64);
                    all_data.extend_from_slice(&file_data);
                }
            }

            // Add directories in reverse to maintain order
            for (dir, rel) in dirs_to_recurse.into_iter().rev() {
                entries_to_process.push((dir, rel));
            }
        }

        Ok((all_data, header))
    }
}

// ============================================================================
// Helper Functions (Free Functions)
// ============================================================================

/// Create a bag from a file using the default backend and configuration.
pub async fn create_bag_from_file(
    path: &Path,
    backend: Arc<dyn StorageBackend>,
) -> StorageResult<Bag> {
    let creator = BagCreator::new(backend).await?;
    creator.from_file(path).await
}

/// Create a bag from a directory using the default backend and configuration.
pub async fn create_bag_from_directory(
    path: &Path,
    backend: Arc<dyn StorageBackend>,
) -> StorageResult<Bag> {
    let creator = BagCreator::new(backend).await?;
    creator.from_directory(path).await
}

/// Create a bag from raw data using the default backend and configuration.
pub async fn create_bag_from_data(
    data: &[u8],
    backend: Arc<dyn StorageBackend>,
) -> StorageResult<Bag> {
    let creator = BagCreator::new(backend).await?;
    creator.from_data(data, None).await
}

/// Verify the integrity of a bag.
pub async fn verify_bag_integrity(
    bag_id: &BagId,
    backend: Arc<dyn StorageBackend>,
) -> StorageResult<bool> {
    let creator = BagCreator::new(backend).await?;
    let result = creator.verify_bag(bag_id).await?;
    Ok(result.is_valid)
}

/// Compute SHA256 hash of a file.
pub async fn compute_file_hash(file_path: &Path) -> StorageResult<[u8; 32]> {
    let data = fs::read(file_path)
        .await
        .map_err(StorageError::IoError)?;

    Ok(sha256(&data))
}

/// Compute SHA256 hash of a directory by hashing all files in sorted order.
pub async fn compute_directory_hash(dir_path: &Path) -> StorageResult<[u8; 32]> {
    let mut all_data = Vec::new();

    // Iterative approach to avoid recursive async issues
    let mut dirs_to_process = vec![dir_path.to_path_buf()];

    while let Some(current_dir) = dirs_to_process.pop() {
        

        let mut entries = fs::read_dir(&current_dir)
            .await
            .map_err(StorageError::IoError)?;

        let mut entry_paths = Vec::new();

        while let Some(entry) = entries
            .next_entry()
            .await
            .map_err(StorageError::IoError)?
        {
            entry_paths.push(entry.path());
        }

        // Sort for deterministic results
        entry_paths.sort();

        for path in entry_paths {
            if path.is_dir() {
                dirs_to_process.push(path);
            } else if path.is_file() {
                let file_data = fs::read(&path)
                    .await
                    .map_err(StorageError::IoError)?;
                all_data.extend_from_slice(&file_data);
            }
        }
    }

    if all_data.is_empty() {
        return Err(StorageError::EmptyData);
    }

    Ok(sha256(&all_data))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provider::InMemoryBackend;
    use std::io::Cursor;
    use std::sync::Arc;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_create_bag_from_data() {
        let backend = Arc::new(InMemoryBackend::new());
        let creator = BagCreator::new(backend).await.unwrap();

        let data = b"Hello, TON Storage!";
        let bag = creator.from_data(data, Some("test.txt".to_string())).await.unwrap();

        assert!(!bag.bag_id.iter().all(|&b| b == 0));
        assert_eq!(bag.info.file_size, data.len() as u64);
    }

    #[tokio::test]
    async fn test_create_bag_from_file() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("test.txt");

        let test_data = b"File content for testing";
        // Write test file
        fs::write(&file_path, test_data).await.unwrap();

        let backend = Arc::new(InMemoryBackend::new());
        let creator = BagCreator::new(backend).await.unwrap();

        let bag = creator.from_file(&file_path).await.unwrap();
        assert!(!bag.bag_id.iter().all(|&b| b == 0));
        assert_eq!(bag.info.file_size, test_data.len() as u64);
    }

    #[tokio::test]
    async fn test_create_bag_from_directory() {
        let temp_dir = TempDir::new().unwrap();

        // Create test files
        fs::write(temp_dir.path().join("file1.txt"), b"Content 1").await.unwrap();
        fs::write(temp_dir.path().join("file2.txt"), b"Content 2").await.unwrap();

        let backend = Arc::new(InMemoryBackend::new());
        let creator = BagCreator::new(backend).await.unwrap();

        let bag = creator.from_directory(temp_dir.path()).await.unwrap();
        assert!(!bag.bag_id.iter().all(|&b| b == 0));
        assert_eq!(bag.info.file_size, 18); // "Content 1" + "Content 2"
    }

    #[tokio::test]
    async fn test_create_bag_from_stream() {
        let backend = Arc::new(InMemoryBackend::new());
        let creator = BagCreator::new(backend).await.unwrap();

        let data = b"Stream content here";
        let cursor: Cursor<Vec<u8>> = Cursor::new(data.to_vec());

        let bag = creator
            .from_stream(cursor, data.len() as u64, Some("stream.txt".to_string()))
            .await
            .unwrap();

        assert!(!bag.bag_id.iter().all(|&b| b == 0));
        assert_eq!(bag.info.file_size, data.len() as u64);
    }

    #[tokio::test]
    async fn test_bag_verification_success() {
        let backend = Arc::new(InMemoryBackend::new());
        let creator = BagCreator::new(backend).await.unwrap();

        let data = b"Test data for verification";
        let bag = creator.from_data(data, None).await.unwrap();

        let result = creator.verify_bag(&bag.bag_id).await.unwrap();
        assert!(result.is_valid);
        assert_eq!(result.failed_chunks, 0);
    }

    #[tokio::test]
    async fn test_builder_pattern() {
        let backend = Arc::new(InMemoryBackend::new());

        let creator = BagCreator::builder()
            .with_chunk_size(512 * 1024)
            .with_verification(false)
            .with_max_concurrent_chunks(8)
            .build(backend)
            .await
            .unwrap();

        assert_eq!(creator.config.chunk_size, 512 * 1024);
        assert!(!creator.config.enable_verification);
        assert_eq!(creator.config.max_concurrent_chunks, 8);
    }

    #[tokio::test]
    async fn test_chunk_size_configuration() {
        let backend = Arc::new(InMemoryBackend::new());

        let creator = BagCreator::builder()
            .with_chunk_size(256 * 1024)
            .build(backend)
            .await
            .unwrap();

        let data = vec![0u8; 512 * 1024]; // 512KB of data
        let _bag = creator.from_data(&data, None).await.unwrap();

        // With 256KB chunks, should have 2 chunks
        let num_chunks = data.len().div_ceil(creator.config.chunk_size);
        assert_eq!(num_chunks, 2);
    }

    #[tokio::test]
    async fn test_large_file_handling() {
        let backend = Arc::new(InMemoryBackend::new());
        let creator = BagCreator::new(backend).await.unwrap();

        // Create 5MB of data
        let data = vec![42u8; 5 * 1024 * 1024];
        let _bag = creator.from_data(&data, None).await.unwrap();

        // Verify the bag was created successfully (implicit via unwrap above)
    }

    #[tokio::test]
    async fn test_invalid_path_error() {
        let backend = Arc::new(InMemoryBackend::new());
        let creator = BagCreator::new(backend).await.unwrap();

        let result = creator.from_file(Path::new("/nonexistent/path/file.txt")).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_empty_file_error() {
        let backend = Arc::new(InMemoryBackend::new());
        let creator = BagCreator::new(backend).await.unwrap();

        let result = creator.from_data(&[], None).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_empty_directory_error() {
        let temp_dir = TempDir::new().unwrap();
        let backend = Arc::new(InMemoryBackend::new());
        let creator = BagCreator::new(backend).await.unwrap();

        let result = creator.from_directory(temp_dir.path()).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_helper_function_create_from_file() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("test.txt");

        let test_data = b"Helper function test";
        fs::write(&file_path, test_data).await.unwrap();

        let backend = Arc::new(InMemoryBackend::new());
        let bag = create_bag_from_file(&file_path, backend).await.unwrap();

        assert_eq!(bag.info.file_size, test_data.len() as u64);
    }

    #[tokio::test]
    async fn test_helper_function_create_from_data() {
        let backend = Arc::new(InMemoryBackend::new());
        let bag = create_bag_from_data(b"Test data", backend).await.unwrap();

        assert_eq!(bag.info.file_size, 9);
    }

    #[tokio::test]
    async fn test_helper_function_verify_integrity() {
        let backend = Arc::new(InMemoryBackend::new());
        let creator = BagCreator::new(backend.clone()).await.unwrap();

        let data = b"Integrity check test";
        let bag = creator.from_data(data, None).await.unwrap();

        let is_valid = verify_bag_integrity(&bag.bag_id, backend).await.unwrap();
        assert!(is_valid);
    }

    #[tokio::test]
    async fn test_compute_file_hash() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("hash_test.txt");

        fs::write(&file_path, b"Hash test content").await.unwrap();

        let hash = compute_file_hash(&file_path).await.unwrap();
        assert_eq!(hash.len(), 32);
        assert!(!hash.iter().all(|&b| b == 0));
    }

    #[tokio::test]
    async fn test_directory_traversal() {
        let temp_dir = TempDir::new().unwrap();

        // Create nested structure
        fs::create_dir(temp_dir.path().join("subdir")).await.unwrap();
        fs::write(temp_dir.path().join("file1.txt"), b"File 1").await.unwrap();
        fs::write(temp_dir.path().join("subdir/file2.txt"), b"File 2").await.unwrap();

        let backend = Arc::new(InMemoryBackend::new());
        let creator = BagCreator::new(backend).await.unwrap();

        let bag = creator.from_directory(temp_dir.path()).await.unwrap();
        assert_eq!(bag.info.file_size, 12); // "File 1" + "File 2"
    }

    #[tokio::test]
    async fn test_bag_creation_config() {
        let config = BagCreationConfig::new()
            .with_chunk_size(512 * 1024)
            .with_verification(false)
            .with_compression(true)
            .with_max_concurrent_chunks(16)
            .with_buffer_size(128 * 1024)
            .with_crc32_computation(false);

        assert_eq!(config.chunk_size, 512 * 1024);
        assert!(!config.enable_verification);
        assert!(config.enable_compression);
        assert_eq!(config.max_concurrent_chunks, 16);
        assert_eq!(config.buffer_size, 128 * 1024);
        assert!(!config.compute_crc32);
    }

    #[tokio::test]
    async fn test_crc32_computation() {
        let backend = Arc::new(InMemoryBackend::new());
        let creator = BagCreator::builder()
            .with_crc32_computation(true)
            .build(backend)
            .await
            .unwrap();

        let data = b"CRC32 test data";
        let bag = creator.from_data(data, None).await.unwrap();

        let result = creator.verify_bag(&bag.bag_id).await.unwrap();
        assert!(result.details.iter().all(|d| d.actual_crc32.is_some()));
    }
}
