//! Storage provider implementations and abstractions.
//!
//! This module provides the core abstractions and implementations for storage backends,
//! including in-memory and file-system based storage for bags. Providers are responsible
//! for persisting, retrieving, and managing stored bags.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use tokio::fs;
use tokio::sync::RwLock;
use tracing::debug;

use crate::bag::BagId;
use crate::error::{ProviderError, StorageResult};

/// Configuration for persistent storage backends.
///
/// Controls capacity limits, checksum verification, and automatic cleanup behavior.
#[derive(Debug, Clone)]
pub struct PersistenceConfig {
    /// Maximum number of bags to store. None means unlimited.
    pub max_bags: Option<usize>,

    /// Maximum storage size in bytes. None means unlimited.
    pub max_size_bytes: Option<u64>,

    /// Whether to compute and verify checksums for all stored data.
    pub enable_checksums: bool,

    /// Whether to automatically clean up expired or corrupted bags.
    pub auto_cleanup: bool,
}

impl PersistenceConfig {
    /// Create a new configuration with default settings.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set maximum number of bags.
    pub fn with_max_bags(mut self, max_bags: usize) -> Self {
        self.max_bags = Some(max_bags);
        self
    }

    /// Set maximum storage size in bytes.
    pub fn with_max_size(mut self, max_size_bytes: u64) -> Self {
        self.max_size_bytes = Some(max_size_bytes);
        self
    }

    /// Enable or disable checksum verification.
    pub fn with_checksums(mut self, enable: bool) -> Self {
        self.enable_checksums = enable;
        self
    }

    /// Enable or disable automatic cleanup.
    pub fn with_auto_cleanup(mut self, enable: bool) -> Self {
        self.auto_cleanup = enable;
        self
    }
}

impl Default for PersistenceConfig {
    fn default() -> Self {
        Self {
            max_bags: None,
            max_size_bytes: None,
            enable_checksums: false,
            auto_cleanup: true,
        }
    }
}

/// Statistics about a storage backend.
#[derive(Debug, Clone)]
pub struct BackendStats {
    /// Total number of bags currently stored.
    pub total_bags: usize,

    /// Total size of all stored bags in bytes.
    pub total_size: u64,

    /// Last time any bag was accessed.
    pub last_access: Option<std::time::Instant>,
}

impl BackendStats {
    /// Create new statistics.
    pub fn new() -> Self {
        Self {
            total_bags: 0,
            total_size: 0,
            last_access: None,
        }
    }

    /// Update last access time.
    fn update_access(&mut self) {
        self.last_access = Some(std::time::Instant::now());
    }
}

impl Default for BackendStats {
    fn default() -> Self {
        Self::new()
    }
}

/// Abstract storage backend trait.
///
/// Defines the interface for all storage implementations, allowing for pluggable
/// backends (in-memory, file-system, database, etc.). All methods are async and
/// return `StorageResult` for consistent error handling.
#[async_trait::async_trait]
pub trait StorageBackend: Send + Sync {
    /// Store a bag's data by its ID.
    async fn store_bag(&self, bag_id: &BagId, data: &[u8]) -> StorageResult<()>;

    /// Retrieve a complete bag's data by ID.
    async fn get_bag(&self, bag_id: &BagId) -> StorageResult<Option<Vec<u8>>>;

    /// Retrieve a specific piece (chunk) of a bag.
    async fn get_piece(&self, bag_id: &BagId, piece_idx: u32) -> StorageResult<Option<Vec<u8>>>;

    /// Check if a bag exists in storage.
    async fn has_bag(&self, bag_id: &BagId) -> StorageResult<bool>;

    /// List all bag IDs currently in storage.
    async fn list_bags(&self) -> StorageResult<Vec<BagId>>;

    /// Delete a bag from storage.
    async fn delete_bag(&self, bag_id: &BagId) -> StorageResult<()>;

    /// Estimate the size of a stored bag.
    async fn estimate_size(&self, bag_id: &BagId) -> StorageResult<u64>;

    /// Get statistics about the storage backend.
    async fn get_stats(&self) -> StorageResult<BackendStats>;
}

/// In-memory storage backend using HashMap.
///
/// Suitable for testing and temporary storage. Uses Arc<RwLock<>> for thread-safe
/// concurrent access. All data is lost when the backend is dropped.
pub struct InMemoryBackend {
    bags: Arc<RwLock<HashMap<Vec<u8>, Vec<u8>>>>,
    stats: Arc<RwLock<BackendStats>>,
    config: PersistenceConfig,
}

impl InMemoryBackend {
    /// Create a new in-memory backend.
    pub fn new() -> Self {
        Self::with_config(PersistenceConfig::default())
    }

    /// Create a new in-memory backend with custom configuration.
    pub fn with_config(config: PersistenceConfig) -> Self {
        Self {
            bags: Arc::new(RwLock::new(HashMap::new())),
            stats: Arc::new(RwLock::new(BackendStats::new())),
            config,
        }
    }
}

impl Default for InMemoryBackend {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl StorageBackend for InMemoryBackend {
    async fn store_bag(&self, bag_id: &BagId, data: &[u8]) -> StorageResult<()> {
        let key = bag_id.to_vec();
        let data_len = data.len() as u64;

        let mut bags = self.bags.write().await;
        let mut stats = self.stats.write().await;

        // Check capacity limits
        if let Some(max_bags) = self.config.max_bags
            && bags.len() >= max_bags && !bags.contains_key(&key) {
                return Err(ProviderError::CapacityExceeded {
                    max_bytes: self.config.max_size_bytes.unwrap_or(0),
                }
                .into());
            }

        if let Some(max_size) = self.config.max_size_bytes {
            let current_size: u64 = bags.values().map(|v| v.len() as u64).sum();
            if current_size + data_len > max_size && !bags.contains_key(&key) {
                return Err(ProviderError::CapacityExceeded {
                    max_bytes: max_size,
                }
                .into());
            }
        }

        // Store the bag
        if let Some(old_data) = bags.insert(key, data.to_vec()) {
            stats.total_size = stats.total_size.saturating_sub(old_data.len() as u64);
        } else {
            stats.total_bags += 1;
        }
        stats.total_size += data_len;
        stats.update_access();

        debug!("Stored bag in memory: {} bytes", data_len);
        Ok(())
    }

    async fn get_bag(&self, bag_id: &BagId) -> StorageResult<Option<Vec<u8>>> {
        let key = bag_id.to_vec();
        let bags = self.bags.read().await;
        let mut stats = self.stats.write().await;

        let result = bags.get(&key).cloned();
        if result.is_some() {
            stats.update_access();
        }

        Ok(result)
    }

    async fn get_piece(&self, bag_id: &BagId, piece_idx: u32) -> StorageResult<Option<Vec<u8>>> {
        let key = bag_id.to_vec();
        let bags = self.bags.read().await;
        let mut stats = self.stats.write().await;

        if let Some(data) = bags.get(&key) {
            let piece_size = 128 * 1024; // Standard chunk size
            let start = (piece_idx as usize) * piece_size;
            let end = std::cmp::min(start + piece_size, data.len());

            if start < data.len() {
                stats.update_access();
                return Ok(Some(data[start..end].to_vec()));
            }
        }

        Ok(None)
    }

    async fn has_bag(&self, bag_id: &BagId) -> StorageResult<bool> {
        let key = bag_id.to_vec();
        let bags = self.bags.read().await;
        Ok(bags.contains_key(&key))
    }

    async fn list_bags(&self) -> StorageResult<Vec<BagId>> {
        let bags = self.bags.read().await;
        let mut result: Vec<BagId> = bags
            .keys()
            .map(|k| {
                let mut bag_id = [0u8; 32];
                if k.len() >= 32 {
                    bag_id.copy_from_slice(&k[..32]);
                }
                bag_id
            })
            .collect();
        result.sort();
        Ok(result)
    }

    async fn delete_bag(&self, bag_id: &BagId) -> StorageResult<()> {
        let key = bag_id.to_vec();
        let mut bags = self.bags.write().await;
        let mut stats = self.stats.write().await;

        if let Some(data) = bags.remove(&key) {
            stats.total_bags = stats.total_bags.saturating_sub(1);
            stats.total_size = stats.total_size.saturating_sub(data.len() as u64);
            stats.update_access();
            debug!("Deleted bag from memory");
        }

        Ok(())
    }

    async fn estimate_size(&self, bag_id: &BagId) -> StorageResult<u64> {
        let key = bag_id.to_vec();
        let bags = self.bags.read().await;

        Ok(bags
            .get(&key)
            .map(|data| data.len() as u64)
            .unwrap_or(0))
    }

    async fn get_stats(&self) -> StorageResult<BackendStats> {
        let stats = self.stats.read().await;
        Ok(stats.clone())
    }
}

/// File-system based storage backend.
///
/// Stores bags as files on disk in a configurable directory. Each bag is stored
/// as a single file named `{root_dir}/{bag_id_hex}.bag`. Supports concurrent
/// access via tokio's async file operations.
pub struct FileSystemBackend {
    root_dir: PathBuf,
    stats: Arc<RwLock<BackendStats>>,
    config: PersistenceConfig,
}

impl FileSystemBackend {
    /// Create a new file-system backend with the given root directory.
    ///
    /// The directory will be created if it doesn't exist.
    pub async fn new<P: AsRef<Path>>(root_dir: P) -> StorageResult<Self> {
        let root_dir = root_dir.as_ref().to_path_buf();

        // Create directory if it doesn't exist
        if !root_dir.exists() {
            fs::create_dir_all(&root_dir).await?;
        }

        Ok(Self {
            root_dir,
            stats: Arc::new(RwLock::new(BackendStats::new())),
            config: PersistenceConfig::default(),
        })
    }

    /// Create a new file-system backend with custom configuration.
    pub async fn with_config<P: AsRef<Path>>(
        root_dir: P,
        config: PersistenceConfig,
    ) -> StorageResult<Self> {
        let root_dir = root_dir.as_ref().to_path_buf();

        // Create directory if it doesn't exist
        if !root_dir.exists() {
            fs::create_dir_all(&root_dir).await?;
        }

        Ok(Self {
            root_dir,
            stats: Arc::new(RwLock::new(BackendStats::new())),
            config,
        })
    }

    /// Get the file path for a bag.
    fn bag_path(&self, bag_id: &BagId) -> PathBuf {
        let hex = hex::encode(bag_id);
        self.root_dir.join(format!("{}.bag", hex))
    }

    /// Calculate total size of all bags.
    async fn calculate_total_size(&self) -> StorageResult<u64> {
        let mut total = 0u64;

        let mut entries = fs::read_dir(&self.root_dir).await?;
        while let Some(entry) = entries.next_entry().await? {
            let metadata = entry.metadata().await?;
            if metadata.is_file() {
                total += metadata.len();
            }
        }

        Ok(total)
    }
}

#[async_trait::async_trait]
impl StorageBackend for FileSystemBackend {
    async fn store_bag(&self, bag_id: &BagId, data: &[u8]) -> StorageResult<()> {
        let path = self.bag_path(bag_id);
        let data_len = data.len() as u64;

        // Check capacity limits
        if let Some(max_size) = self.config.max_size_bytes
            && !path.exists() {
                let current_size = self.calculate_total_size().await?;
                if current_size + data_len > max_size {
                    return Err(ProviderError::CapacityExceeded {
                        max_bytes: max_size,
                    }
                    .into());
                }
            }

        // Write the bag to disk
        fs::write(&path, data).await?;

        // Update statistics
        let mut stats = self.stats.write().await;
        stats.total_bags = self.list_bags().await?.len();
        stats.total_size = self.calculate_total_size().await?;
        stats.update_access();

        debug!("Stored bag on filesystem: {}", path.display());
        Ok(())
    }

    async fn get_bag(&self, bag_id: &BagId) -> StorageResult<Option<Vec<u8>>> {
        let path = self.bag_path(bag_id);

        if !path.exists() {
            return Ok(None);
        }

        let data = fs::read(&path).await?;

        let mut stats = self.stats.write().await;
        stats.update_access();

        Ok(Some(data))
    }

    async fn get_piece(&self, bag_id: &BagId, piece_idx: u32) -> StorageResult<Option<Vec<u8>>> {
        let path = self.bag_path(bag_id);

        if !path.exists() {
            return Ok(None);
        }

        let data = fs::read(&path).await?;
        let piece_size = 128 * 1024; // Standard chunk size
        let start = (piece_idx as usize) * piece_size;
        let end = std::cmp::min(start + piece_size, data.len());

        if start < data.len() {
            let mut stats = self.stats.write().await;
            stats.update_access();
            return Ok(Some(data[start..end].to_vec()));
        }

        Ok(None)
    }

    async fn has_bag(&self, bag_id: &BagId) -> StorageResult<bool> {
        let path = self.bag_path(bag_id);
        Ok(path.exists())
    }

    async fn list_bags(&self) -> StorageResult<Vec<BagId>> {
        let mut result = Vec::new();

        if !self.root_dir.exists() {
            return Ok(result);
        }

        let mut entries = fs::read_dir(&self.root_dir).await?;
        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();
            if path.is_file()
                && let Some(name) = path.file_stem()
                    && let Some(name_str) = name.to_str()
                        && let Ok(bytes) = hex::decode(name_str)
                            && bytes.len() == 32 {
                                let mut bag_id = [0u8; 32];
                                bag_id.copy_from_slice(&bytes);
                                result.push(bag_id);
                            }
        }

        result.sort();
        Ok(result)
    }

    async fn delete_bag(&self, bag_id: &BagId) -> StorageResult<()> {
        let path = self.bag_path(bag_id);

        if path.exists() {
            fs::remove_file(&path).await?;

            let mut stats = self.stats.write().await;
            stats.total_bags = self.list_bags().await?.len();
            stats.total_size = self.calculate_total_size().await?;
            stats.update_access();

            debug!("Deleted bag from filesystem");
        }

        Ok(())
    }

    async fn estimate_size(&self, bag_id: &BagId) -> StorageResult<u64> {
        let path = self.bag_path(bag_id);

        if !path.exists() {
            return Ok(0);
        }

        let metadata = fs::metadata(&path).await?;
        Ok(metadata.len())
    }

    async fn get_stats(&self) -> StorageResult<BackendStats> {
        let stats = self.stats.read().await;
        Ok(stats.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_in_memory_backend_store_and_get() {
        let backend = InMemoryBackend::new();
        let bag_id = [1u8; 32];
        let data = b"test data";

        // Store
        backend.store_bag(&bag_id, data).await.unwrap();

        // Retrieve
        let retrieved = backend.get_bag(&bag_id).await.unwrap();
        assert_eq!(retrieved, Some(data.to_vec()));
    }

    #[tokio::test]
    async fn test_in_memory_backend_has_bag() {
        let backend = InMemoryBackend::new();
        let bag_id = [2u8; 32];

        assert!(!backend.has_bag(&bag_id).await.unwrap());

        backend.store_bag(&bag_id, b"test").await.unwrap();
        assert!(backend.has_bag(&bag_id).await.unwrap());
    }

    #[tokio::test]
    async fn test_in_memory_backend_list_bags() {
        let backend = InMemoryBackend::new();
        let bag_id1 = [1u8; 32];
        let bag_id2 = [2u8; 32];

        backend.store_bag(&bag_id1, b"data1").await.unwrap();
        backend.store_bag(&bag_id2, b"data2").await.unwrap();

        let bags = backend.list_bags().await.unwrap();
        assert_eq!(bags.len(), 2);
    }

    #[tokio::test]
    async fn test_in_memory_backend_delete_bag() {
        let backend = InMemoryBackend::new();
        let bag_id = [3u8; 32];

        backend.store_bag(&bag_id, b"test").await.unwrap();
        assert!(backend.has_bag(&bag_id).await.unwrap());

        backend.delete_bag(&bag_id).await.unwrap();
        assert!(!backend.has_bag(&bag_id).await.unwrap());
    }

    #[tokio::test]
    async fn test_in_memory_backend_estimate_size() {
        let backend = InMemoryBackend::new();
        let bag_id = [4u8; 32];
        let data = b"test data content";

        backend.store_bag(&bag_id, data).await.unwrap();
        let size = backend.estimate_size(&bag_id).await.unwrap();
        assert_eq!(size, data.len() as u64);
    }

    #[tokio::test]
    async fn test_in_memory_backend_get_stats() {
        let backend = InMemoryBackend::new();
        let bag_id = [5u8; 32];
        let data = b"test";

        let stats_before = backend.get_stats().await.unwrap();
        assert_eq!(stats_before.total_bags, 0);

        backend.store_bag(&bag_id, data).await.unwrap();

        let stats_after = backend.get_stats().await.unwrap();
        assert_eq!(stats_after.total_bags, 1);
        assert_eq!(stats_after.total_size, data.len() as u64);
    }

    #[tokio::test]
    async fn test_filesystem_backend_basic() {
        let temp_dir = tempfile::tempdir().unwrap();
        let backend = FileSystemBackend::new(temp_dir.path()).await.unwrap();

        let bag_id = [6u8; 32];
        let data = b"filesystem test data";

        // Store
        backend.store_bag(&bag_id, data).await.unwrap();

        // Retrieve
        let retrieved = backend.get_bag(&bag_id).await.unwrap();
        assert_eq!(retrieved, Some(data.to_vec()));

        // Cleanup
        drop(temp_dir);
    }

    #[tokio::test]
    async fn test_persistence_config_builder() {
        let config = PersistenceConfig::new()
            .with_max_bags(100)
            .with_max_size(1024 * 1024)
            .with_checksums(true)
            .with_auto_cleanup(false);

        assert_eq!(config.max_bags, Some(100));
        assert_eq!(config.max_size_bytes, Some(1024 * 1024));
        assert!(config.enable_checksums);
        assert!(!config.auto_cleanup);
    }

    #[test]
    fn test_backend_stats_creation() {
        let stats = BackendStats::new();
        assert_eq!(stats.total_bags, 0);
        assert_eq!(stats.total_size, 0);
        assert!(stats.last_access.is_none());
    }
}
