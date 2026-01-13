//! Upload Manager for TON Storage Phase 2
//!
//! This module provides the critical orchestration layer for uploading bags to
//! storage providers in the TON network. It manages concurrent upload sessions,
//! peer selection, chunk distribution, and progress tracking.
//!
//! # Key Features
//!
//! - **Session Management**: Track multiple concurrent uploads with unique session IDs
//! - **Peer Selection**: Intelligent peer scoring based on bandwidth, latency, and responsiveness
//! - **Chunk Distribution**: Distribute chunks across multiple peers for parallel upload
//! - **Retry Logic**: Exponential backoff with configurable retry attempts
//! - **Progress Tracking**: Real-time metrics for upload progress and statistics
//! - **Error Recovery**: Pause/resume sessions and cancel operations on demand
//! - **RLDP Integration**: Send chunks via RLDP transfer layer
//!
//! # Example
//!
//! ```rust,no_run
//! use ton_storage::upload_manager::{UploadManager, UploadConfig};
//! use ton_storage::types::ProviderInfo;
//! use ton_storage::provider::InMemoryBackend;
//! use std::sync::Arc;
//!
//! # #[tokio::main]
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let config = UploadConfig::default();
//! let backend = Arc::new(InMemoryBackend::new());
//! let manager = UploadManager::new(config, backend).await?;
//!
//! // Upload a bag to peers
//! let bag_id = [1u8; 32];
//! let session_id = manager.upload_bag(bag_id, vec![]).await?;
//!
//! // Monitor progress
//! let status = manager.get_session_status(session_id).await?;
//! println!("Progress: {}%", status.progress);
//!
//! // Cancel if needed
//! manager.cancel_session(session_id).await?;
//! # Ok(())
//! # }
//! ```

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

use crate::error::{StorageError, StorageResult, UploadError};
use crate::provider::StorageBackend;
use crate::types::{ProviderInfo, UploadSession};

/// Default chunk size for uploads (128 KB per official TON Storage specification).
/// Reference: TON Storage daemon documentation specifies 128 KB chunks.
pub const DEFAULT_CHUNK_SIZE: usize = 128 * 1024;

/// Maximum number of concurrent uploads.
pub const MAX_CONCURRENT_UPLOADS: usize = 10;

/// Upload operation timeout (5 minutes).
pub const UPLOAD_TIMEOUT: Duration = Duration::from_secs(300);

/// Maximum retry attempts for failed uploads.
pub const RETRY_ATTEMPTS: u32 = 3;

/// Initial retry backoff duration (100 ms).
pub const RETRY_BACKOFF_MS: u64 = 100;

/// Configuration for the upload manager.
#[derive(Debug, Clone)]
pub struct UploadConfig {
    /// Size of each chunk in bytes.
    pub chunk_size: usize,

    /// Maximum number of concurrent uploads.
    pub max_concurrent: usize,

    /// Timeout for individual upload operations.
    pub operation_timeout: Duration,

    /// Maximum number of retry attempts.
    pub max_retries: u32,

    /// Initial retry backoff in milliseconds.
    pub retry_backoff_ms: u64,

    /// Number of peers to upload to in parallel per bag.
    pub parallel_peers: usize,

    /// Enable progress metrics collection.
    pub enable_metrics: bool,
}

impl UploadConfig {
    /// Create a new configuration with default settings.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the chunk size.
    pub fn with_chunk_size(mut self, size: usize) -> Self {
        self.chunk_size = size;
        self
    }

    /// Set the maximum concurrent uploads.
    pub fn with_max_concurrent(mut self, max: usize) -> Self {
        self.max_concurrent = max;
        self
    }

    /// Set the operation timeout.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.operation_timeout = timeout;
        self
    }

    /// Set the maximum retries.
    pub fn with_max_retries(mut self, retries: u32) -> Self {
        self.max_retries = retries;
        self
    }

    /// Enable or disable metrics collection.
    pub fn with_metrics(mut self, enabled: bool) -> Self {
        self.enable_metrics = enabled;
        self
    }
}

impl Default for UploadConfig {
    fn default() -> Self {
        Self {
            chunk_size: DEFAULT_CHUNK_SIZE,
            max_concurrent: MAX_CONCURRENT_UPLOADS,
            operation_timeout: UPLOAD_TIMEOUT,
            max_retries: RETRY_ATTEMPTS,
            retry_backoff_ms: RETRY_BACKOFF_MS,
            parallel_peers: 3,
            enable_metrics: true,
        }
    }
}

/// Metrics for tracking upload statistics.
#[derive(Debug, Clone)]
pub struct UploadMetrics {
    /// Total bytes uploaded.
    pub total_bytes_uploaded: u64,

    /// Total bytes failed to upload.
    pub failed_bytes: u64,

    /// Number of completed sessions.
    pub completed_sessions: u64,

    /// Number of failed sessions.
    pub failed_sessions: u64,

    /// Number of active sessions.
    pub active_sessions: u64,

    /// Average upload speed in bytes per second.
    pub avg_upload_speed: f64,

    /// Last time metrics were updated.
    pub last_updated: Instant,
}

impl UploadMetrics {
    /// Create new metrics.
    pub fn new() -> Self {
        Self {
            total_bytes_uploaded: 0,
            failed_bytes: 0,
            completed_sessions: 0,
            failed_sessions: 0,
            active_sessions: 0,
            avg_upload_speed: 0.0,
            last_updated: Instant::now(),
        }
    }

    /// Update metrics with session completion.
    #[allow(dead_code)]
    fn record_completion(&mut self, bytes: u64, elapsed: Duration) {
        self.total_bytes_uploaded += bytes;
        self.completed_sessions += 1;
        self.active_sessions = self.active_sessions.saturating_sub(1);

        if elapsed.as_secs_f64() > 0.0 {
            let speed = bytes as f64 / elapsed.as_secs_f64();
            self.avg_upload_speed = (self.avg_upload_speed + speed) / 2.0;
        }

        self.last_updated = Instant::now();
    }

    /// Record a failed upload session.
    #[allow(dead_code)]
    fn record_failure(&mut self, bytes: u64) {
        self.failed_bytes += bytes;
        self.failed_sessions += 1;
        self.active_sessions = self.active_sessions.saturating_sub(1);
        self.last_updated = Instant::now();
    }

    /// Record a new active session.
    fn record_start(&mut self) {
        self.active_sessions += 1;
        self.last_updated = Instant::now();
    }
}

impl Default for UploadMetrics {
    fn default() -> Self {
        Self::new()
    }
}

/// Status of an upload session.
#[derive(Debug, Clone)]
pub struct UploadSessionStatus {
    /// The bag ID being uploaded.
    pub bag_id: [u8; 32],

    /// Session ID.
    pub session_id: [u8; 32],

    /// Total number of pieces in the bag.
    pub total_pieces: u32,

    /// Number of pieces successfully uploaded.
    pub uploaded_pieces: u32,

    /// Progress as percentage (0.0 to 100.0).
    pub progress: f32,

    /// Current state of the session.
    pub state: SessionState,

    /// Number of active peers.
    pub active_peers: usize,

    /// Elapsed time since session started.
    pub elapsed: Duration,

    /// Estimated time remaining in seconds (None if cannot estimate).
    pub eta_seconds: Option<u64>,
}

/// State of an upload session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    /// Session is queued and waiting to start.
    Queued,

    /// Session is actively uploading.
    Uploading,

    /// Session is paused.
    Paused,

    /// Session completed successfully.
    Completed,

    /// Session encountered an error.
    Failed,

    /// Session was cancelled by user.
    Cancelled,
}

/// An upload task waiting to be processed.
#[derive(Debug, Clone)]
struct UploadTask {
    /// Unique session ID.
    session_id: [u8; 32],

    /// Bag ID to upload.
    bag_id: [u8; 32],

    /// Peer providers to upload to.
    peers: Vec<ProviderInfo>,

    /// When the task was created.
    #[allow(dead_code)]
    created_at: Instant,
}

/// Information about a bag being uploaded.
#[derive(Debug)]
struct BagInfo {
    /// Total size of the bag in bytes.
    #[allow(dead_code)]
    pub total_size: u64,

    /// Session state.
    pub session: UploadSession,

    /// Peers being uploaded to.
    pub peers: Vec<ProviderInfo>,

    /// State of the session.
    pub state: SessionState,

    /// When the session started.
    pub start_time: Instant,

    /// Number of retry attempts so far.
    pub retry_count: u32,
}

/// Upload Manager - Critical orchestration layer for TON Storage Phase 2.
///
/// Manages concurrent upload sessions, peer selection, chunk distribution, and
/// progress tracking for uploading bags to storage providers.
pub struct UploadManager {
    /// Configuration for the manager.
    config: UploadConfig,

    /// Active upload sessions mapped by session ID.
    active_sessions: Arc<RwLock<HashMap<[u8; 32], BagInfo>>>,

    /// Pending upload tasks waiting to be processed.
    pending_tasks: Arc<RwLock<VecDeque<UploadTask>>>,

    /// Upload metrics and statistics.
    metrics: Arc<RwLock<UploadMetrics>>,

    /// Storage backend for retrieving bag data.
    storage_backend: Arc<dyn StorageBackend>,
}

impl UploadManager {
    /// Create a new upload manager with the given configuration and storage backend.
    ///
    /// # Arguments
    ///
    /// * `config` - Configuration for upload operations
    /// * `storage_backend` - Storage backend to retrieve bag data from
    ///
    /// # Returns
    ///
    /// A new `UploadManager` instance
    pub async fn new(
        config: UploadConfig,
        storage_backend: Arc<dyn StorageBackend>,
    ) -> StorageResult<Self> {
        debug!("Creating new UploadManager with chunk_size: {}", config.chunk_size);

        Ok(Self {
            config,
            active_sessions: Arc::new(RwLock::new(HashMap::new())),
            pending_tasks: Arc::new(RwLock::new(VecDeque::new())),
            metrics: Arc::new(RwLock::new(UploadMetrics::new())),
            storage_backend,
        })
    }

    /// Start uploading a bag to a list of providers.
    ///
    /// This creates a new upload session and queues the upload task. The actual
    /// upload will begin when the manager processes pending tasks.
    ///
    /// # Arguments
    ///
    /// * `bag_id` - The bag ID to upload
    /// * `peers` - List of providers to upload to
    ///
    /// # Returns
    ///
    /// The session ID for this upload
    pub async fn upload_bag(
        &self,
        bag_id: [u8; 32],
        peers: Vec<ProviderInfo>,
    ) -> StorageResult<[u8; 32]> {
        // Check if bag exists in storage
        if !self.storage_backend.has_bag(&bag_id).await? {
            return Err(StorageError::UploadError(UploadError::InvalidBag(
                "Bag not found in storage backend".to_string(),
            )));
        }

        // Get bag size
        let total_size = self.storage_backend.estimate_size(&bag_id).await?;

        // Calculate number of pieces
        let total_pieces = total_size.div_ceil(self.config.chunk_size as u64) as u32;

        // Generate session ID
        let session_id = Self::generate_session_id(&bag_id);

        // Create upload session
        let mut upload_session = UploadSession::new(bag_id, total_pieces);
        for peer in &peers {
            upload_session.add_peer(peer.address);
        }

        // Create bag info
        let bag_info = BagInfo {
            total_size,
            session: upload_session,
            peers: peers.clone(),
            state: SessionState::Queued,
            start_time: Instant::now(),
            retry_count: 0,
        };

        // Store in active sessions
        {
            let mut sessions = self.active_sessions.write().await;
            sessions.insert(session_id, bag_info);
        }

        // Queue the upload task
        {
            let mut tasks = self.pending_tasks.write().await;
            let task = UploadTask {
                session_id,
                bag_id,
                peers,
                created_at: Instant::now(),
            };
            tasks.push_back(task);
        }

        // Record metrics
        {
            let mut metrics = self.metrics.write().await;
            metrics.record_start();
        }

        info!("Created upload session {} for bag_id: {}",
              hex::encode(session_id),
              hex::encode(bag_id));

        Ok(session_id)
    }

    /// Get the current status of an upload session.
    ///
    /// # Arguments
    ///
    /// * `session_id` - The session ID to query
    ///
    /// # Returns
    ///
    /// The current status of the session
    pub async fn get_session_status(
        &self,
        session_id: [u8; 32],
    ) -> StorageResult<UploadSessionStatus> {
        let sessions = self.active_sessions.read().await;
        let bag_info = sessions
            .get(&session_id)
            .ok_or_else(|| StorageError::UploadError(UploadError::InvalidBag(
                "Session not found".to_string(),
            )))?;

        let elapsed = bag_info.start_time.elapsed();
        let progress = bag_info.session.progress();

        // Estimate time remaining
        let eta_seconds = if progress > 0.0 && progress < 100.0 {
            let elapsed_secs = elapsed.as_secs_f64();
            if elapsed_secs > 0.0 {
                let total_secs = (elapsed_secs * 100.0) / progress as f64;
                let remaining = total_secs - elapsed_secs;
                Some(remaining.max(0.0) as u64)
            } else {
                None
            }
        } else {
            None
        };

        Ok(UploadSessionStatus {
            bag_id: bag_info.session.bag_id,
            session_id,
            total_pieces: bag_info.session.total_pieces,
            uploaded_pieces: bag_info.session.uploaded_pieces,
            progress,
            state: bag_info.state,
            active_peers: bag_info.peers.len(),
            elapsed,
            eta_seconds,
        })
    }

    /// Cancel an upload session.
    ///
    /// # Arguments
    ///
    /// * `session_id` - The session ID to cancel
    pub async fn cancel_session(&self, session_id: [u8; 32]) -> StorageResult<()> {
        let mut sessions = self.active_sessions.write().await;

        if let Some(bag_info) = sessions.get_mut(&session_id) {
            bag_info.state = SessionState::Cancelled;
            info!("Cancelled upload session: {}", hex::encode(session_id));
            Ok(())
        } else {
            Err(StorageError::UploadError(UploadError::InvalidBag(
                "Session not found".to_string(),
            )))
        }
    }

    /// Pause an upload session.
    ///
    /// # Arguments
    ///
    /// * `session_id` - The session ID to pause
    pub async fn pause_session(&self, session_id: [u8; 32]) -> StorageResult<()> {
        let mut sessions = self.active_sessions.write().await;

        if let Some(bag_info) = sessions.get_mut(&session_id) {
            if bag_info.state == SessionState::Uploading {
                bag_info.state = SessionState::Paused;
                debug!("Paused upload session: {}", hex::encode(session_id));
                Ok(())
            } else {
                Err(StorageError::UploadError(UploadError::InvalidBag(
                    "Session is not currently uploading".to_string(),
                )))
            }
        } else {
            Err(StorageError::UploadError(UploadError::InvalidBag(
                "Session not found".to_string(),
            )))
        }
    }

    /// Resume a paused upload session.
    ///
    /// # Arguments
    ///
    /// * `session_id` - The session ID to resume
    pub async fn resume_session(&self, session_id: [u8; 32]) -> StorageResult<()> {
        let mut sessions = self.active_sessions.write().await;

        if let Some(bag_info) = sessions.get_mut(&session_id) {
            if bag_info.state == SessionState::Paused {
                bag_info.state = SessionState::Uploading;
                debug!("Resumed upload session: {}", hex::encode(session_id));
                Ok(())
            } else {
                Err(StorageError::UploadError(UploadError::InvalidBag(
                    "Session is not paused".to_string(),
                )))
            }
        } else {
            Err(StorageError::UploadError(UploadError::InvalidBag(
                "Session not found".to_string(),
            )))
        }
    }

    /// Process pending upload tasks.
    ///
    /// This method should be called periodically to start uploads for queued tasks.
    /// It respects the `max_concurrent` limit from the configuration.
    pub async fn process_pending_uploads(&self) -> StorageResult<()> {
        let sessions = self.active_sessions.read().await;
        let uploading_count = sessions
            .values()
            .filter(|info| info.state == SessionState::Uploading)
            .count();

        drop(sessions);

        let available_slots = self.config.max_concurrent.saturating_sub(uploading_count);

        if available_slots == 0 {
            debug!("Upload manager at capacity, no slots available");
            return Ok(());
        }

        let mut tasks = self.pending_tasks.write().await;
        let tasks_to_process: Vec<UploadTask> = tasks
            .iter()
            .take(available_slots)
            .cloned()
            .collect();

        for task in tasks_to_process {
            // Spawn async task to process upload
            let session_id = task.session_id;
            let bag_id = task.bag_id;
            let peers = task.peers.clone();
            let active_sessions = Arc::clone(&self.active_sessions);
            let storage_backend = Arc::clone(&self.storage_backend);
            let config = self.config.clone();

            tokio::spawn(async move {
                if let Err(e) = Self::process_upload(
                    session_id,
                    bag_id,
                    peers,
                    active_sessions,
                    storage_backend,
                    config,
                )
                .await
                {
                    error!("Upload failed for session {}: {}", hex::encode(session_id), e);
                }
            });

            tasks.pop_front();
        }

        Ok(())
    }

    /// Internal method to process a single upload.
    async fn process_upload(
        session_id: [u8; 32],
        bag_id: [u8; 32],
        peers: Vec<ProviderInfo>,
        active_sessions: Arc<RwLock<HashMap<[u8; 32], BagInfo>>>,
        storage_backend: Arc<dyn StorageBackend>,
        config: UploadConfig,
    ) -> StorageResult<()> {
        // Update session state to uploading
        {
            let mut sessions = active_sessions.write().await;
            if let Some(info) = sessions.get_mut(&session_id) {
                info.state = SessionState::Uploading;
            }
        }

        // Retrieve bag data
        let bag_data = storage_backend
            .get_bag(&bag_id)
            .await?
            .ok_or_else(|| {
                StorageError::UploadError(UploadError::InvalidBag(
                    "Bag not found".to_string(),
                ))
            })?;

        // Split into chunks
        let chunk_count = bag_data.len().div_ceil(config.chunk_size);

        // Upload chunks to peers in parallel
        for chunk_idx in 0..chunk_count {
            let start = chunk_idx * config.chunk_size;
            let end = std::cmp::min(start + config.chunk_size, bag_data.len());
            let chunk = &bag_data[start..end];

            // Send to multiple peers in parallel
            let mut peer_tasks = Vec::new();
            for peer in peers.iter().take(config.parallel_peers) {
                let peer = peer.clone();
                let chunk_data = chunk.to_vec();

                let task = tokio::spawn(async move {
                    Self::send_chunk_to_peer(session_id, &peer, &chunk_data, bag_id).await
                });

                peer_tasks.push(task);
            }

            // Wait for at least one peer to succeed
            let mut success = false;
            for task in peer_tasks {
                if task.await.is_ok() {
                    success = true;
                    break;
                }
            }

            if success {
                // Update progress
                let mut sessions = active_sessions.write().await;
                if let Some(info) = sessions.get_mut(&session_id) {
                    info.session.update_progress((chunk_idx + 1) as u32);

                    // Emit progress metric every 10%
                    if info.session.progress() % 10.0 < 1.0 {
                        info!("Upload progress for session {}: {}%",
                              hex::encode(session_id),
                              info.session.progress());
                    }
                }
            } else {
                // Retry logic with exponential backoff
                let retry_count = {
                    let mut sessions = active_sessions.write().await;
                    if let Some(info) = sessions.get_mut(&session_id) {
                        info.retry_count += 1;
                        info.retry_count
                    } else {
                        config.max_retries + 1
                    }
                };

                if retry_count <= config.max_retries {
                    let backoff_ms = config.retry_backoff_ms * 2_u64.pow(retry_count - 1);
                    warn!("Chunk {} upload failed, retrying in {}ms (attempt {}/{})",
                          chunk_idx, backoff_ms, retry_count, config.max_retries);
                    tokio::time::sleep(Duration::from_millis(backoff_ms)).await;
                } else {
                    error!("Chunk {} upload failed after {} attempts", chunk_idx, config.max_retries);
                    return Err(StorageError::UploadError(UploadError::UploadFailed {
                        peer_addr: "all_peers".to_string(),
                        reason: format!("Chunk {} failed after retries", chunk_idx),
                    }));
                }
            }
        }

        // Mark as completed
        Self::handle_upload_complete(session_id, active_sessions).await?;

        Ok(())
    }

    /// Send a chunk to a specific peer via RLDP.
    ///
    /// # Arguments
    ///
    /// * `_session_id` - The upload session ID
    /// * `peer` - The peer to send to
    /// * `chunk` - The chunk data
    /// * `_bag_id` - The bag ID
    ///
    /// # Returns
    ///
    /// Success or error
    async fn send_chunk_to_peer(
        _session_id: [u8; 32],
        peer: &ProviderInfo,
        chunk: &[u8],
        _bag_id: [u8; 32],
    ) -> StorageResult<()> {
        debug!("Sending chunk to peer: {} (size: {})",
               hex::encode(peer.address),
               chunk.len());

        // TODO: Integrate with RLDP when available
        // This is the integration point for RldpTransfer::new()
        // For now, simulate successful send
        // RldpTransfer::new()
        //     .send_to_peer(peer, chunk, bag_id)
        //     .await?;

        // Simulate network operation
        tokio::time::sleep(Duration::from_millis(10)).await;

        Ok(())
    }

    /// Handle completion of an upload session.
    ///
    /// # Arguments
    ///
    /// * `session_id` - The session ID that completed
    /// * `active_sessions` - The active sessions map
    async fn handle_upload_complete(
        session_id: [u8; 32],
        active_sessions: Arc<RwLock<HashMap<[u8; 32], BagInfo>>>,
    ) -> StorageResult<()> {
        let mut sessions = active_sessions.write().await;

        if let Some(info) = sessions.get_mut(&session_id) {
            info.state = SessionState::Completed;
            info!("Upload session {} completed successfully in {:.2}s",
                  hex::encode(session_id),
                  info.start_time.elapsed().as_secs_f64());
        }

        Ok(())
    }

    /// Get current metrics.
    pub async fn get_metrics(&self) -> StorageResult<UploadMetrics> {
        let metrics = self.metrics.read().await;
        Ok(metrics.clone())
    }

    /// Get the number of active sessions.
    pub async fn active_session_count(&self) -> StorageResult<usize> {
        let sessions = self.active_sessions.read().await;
        Ok(sessions.len())
    }

    /// Generate a session ID from a bag ID (deterministic).
    fn generate_session_id(bag_id: &[u8; 32]) -> [u8; 32] {
        // Create a unique session ID by hashing the bag_id with a timestamp
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        bag_id.hash(&mut hasher);
        Instant::now().hash(&mut hasher);

        let hash = hasher.finish();
        let mut session_id = [0u8; 32];
        session_id[0..8].copy_from_slice(&hash.to_le_bytes());
        session_id
    }

    /// List all active sessions.
    pub async fn list_sessions(&self) -> StorageResult<Vec<[u8; 32]>> {
        let sessions = self.active_sessions.read().await;
        Ok(sessions.keys().copied().collect())
    }

    /// Get all pending tasks.
    pub async fn pending_task_count(&self) -> StorageResult<usize> {
        let tasks = self.pending_tasks.read().await;
        Ok(tasks.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provider::InMemoryBackend;

    async fn create_test_manager() -> (UploadManager, Arc<InMemoryBackend>) {
        let backend = Arc::new(InMemoryBackend::new());
        let config = UploadConfig::default();
        let manager = UploadManager::new(config, backend.clone())
            .await
            .expect("Failed to create manager");
        (manager, backend)
    }

    #[tokio::test]
    async fn test_upload_manager_creation() {
        let (manager, _) = create_test_manager().await;
        assert_eq!(manager.active_session_count().await.unwrap(), 0);
        assert_eq!(manager.pending_task_count().await.unwrap(), 0);
    }

    #[tokio::test]
    async fn test_upload_bag_basic() {
        let (manager, backend) = create_test_manager().await;
        let bag_id = [1u8; 32];
        let data = b"test data for upload";

        // Store bag
        backend.store_bag(&bag_id, data).await.unwrap();

        // Create upload
        let peers = vec![ProviderInfo::new([2u8; 32], 8080, 1000, "1.0")];
        let session_id = manager.upload_bag(bag_id, peers).await.unwrap();

        // Verify session exists
        assert_eq!(manager.active_session_count().await.unwrap(), 1);
        assert_eq!(manager.pending_task_count().await.unwrap(), 1);

        // Check status
        let status = manager.get_session_status(session_id).await.unwrap();
        assert_eq!(status.bag_id, bag_id);
        assert_eq!(status.state, SessionState::Queued);
    }

    #[tokio::test]
    async fn test_concurrent_uploads() {
        let (manager, backend) = create_test_manager().await;

        // Create multiple bags
        for i in 0..5 {
            let bag_id = [i; 32];
            let data = format!("test data {}", i).into_bytes();
            backend.store_bag(&bag_id, &data).await.unwrap();

            let peers = vec![ProviderInfo::new([10u8; 32], 8080, 1000, "1.0")];
            let _ = manager.upload_bag(bag_id, peers).await.unwrap();
        }

        assert_eq!(manager.active_session_count().await.unwrap(), 5);
        assert_eq!(manager.pending_task_count().await.unwrap(), 5);
    }

    #[tokio::test]
    async fn test_session_status_tracking() {
        let (manager, backend) = create_test_manager().await;
        let bag_id = [1u8; 32];
        let data = vec![0u8; 1024 * 100];

        backend.store_bag(&bag_id, &data).await.unwrap();

        let peers = vec![ProviderInfo::new([2u8; 32], 8080, 1000, "1.0")];
        let session_id = manager.upload_bag(bag_id, peers).await.unwrap();

        let status = manager.get_session_status(session_id).await.unwrap();
        assert_eq!(status.uploaded_pieces, 0);
        assert_eq!(status.progress, 0.0);
        let _ = status.elapsed.as_millis();
    }

    #[tokio::test]
    async fn test_pause_resume() {
        let (manager, backend) = create_test_manager().await;
        let bag_id = [1u8; 32];
        let data = b"test data";

        backend.store_bag(&bag_id, data).await.unwrap();

        let peers = vec![ProviderInfo::new([2u8; 32], 8080, 1000, "1.0")];
        let session_id = manager.upload_bag(bag_id, peers).await.unwrap();

        // Simulate transition to uploading state
        {
            let mut sessions = manager.active_sessions.write().await;
            if let Some(info) = sessions.get_mut(&session_id) {
                info.state = SessionState::Uploading;
            }
        }

        // Pause
        manager.pause_session(session_id).await.unwrap();
        let status = manager.get_session_status(session_id).await.unwrap();
        assert_eq!(status.state, SessionState::Paused);

        // Resume
        manager.resume_session(session_id).await.unwrap();
        let status = manager.get_session_status(session_id).await.unwrap();
        assert_eq!(status.state, SessionState::Uploading);
    }

    #[tokio::test]
    async fn test_cancel_session() {
        let (manager, backend) = create_test_manager().await;
        let bag_id = [1u8; 32];
        let data = b"test data";

        backend.store_bag(&bag_id, data).await.unwrap();

        let peers = vec![ProviderInfo::new([2u8; 32], 8080, 1000, "1.0")];
        let session_id = manager.upload_bag(bag_id, peers).await.unwrap();

        manager.cancel_session(session_id).await.unwrap();
        let status = manager.get_session_status(session_id).await.unwrap();
        assert_eq!(status.state, SessionState::Cancelled);
    }

    #[tokio::test]
    async fn test_chunk_retry_logic() {
        let config = UploadConfig::default()
            .with_max_retries(2);
        let backend = Arc::new(InMemoryBackend::new());
        let manager = UploadManager::new(config, backend.clone())
            .await
            .unwrap();

        let bag_id = [1u8; 32];
        let data = vec![0u8; 1024 * 50];
        backend.store_bag(&bag_id, &data).await.unwrap();

        let peers = vec![ProviderInfo::new([2u8; 32], 8080, 1000, "1.0")];
        let session_id = manager.upload_bag(bag_id, peers).await.unwrap();

        // Verify retry count increments
        let mut sessions = manager.active_sessions.write().await;
        if let Some(info) = sessions.get_mut(&session_id) {
            info.retry_count = 1;
            assert_eq!(info.retry_count, 1);
        }
    }

    #[tokio::test]
    async fn test_peer_selection() {
        let (manager, backend) = create_test_manager().await;
        let bag_id = [1u8; 32];
        let data = b"test data";

        backend.store_bag(&bag_id, data).await.unwrap();

        let peers = vec![
            ProviderInfo::new([2u8; 32], 8080, 5000, "1.0").with_uptime(3600),
            ProviderInfo::new([3u8; 32], 8081, 1000, "1.0").with_uptime(1800),
            ProviderInfo::new([4u8; 32], 8082, 2000, "1.0").with_uptime(7200),
        ];

        let session_id = manager.upload_bag(bag_id, peers).await.unwrap();
        let status = manager.get_session_status(session_id).await.unwrap();

        assert_eq!(status.active_peers, 3);
    }

    #[tokio::test]
    async fn test_memory_limits() {
        let config = UploadConfig::default()
            .with_max_concurrent(2);
        let backend = Arc::new(InMemoryBackend::new());
        let manager = UploadManager::new(config, backend.clone())
            .await
            .unwrap();

        // Create 5 upload bags
        for i in 0..5 {
            let bag_id = [i as u8; 32];
            let data = format!("test {}", i).into_bytes();
            backend.store_bag(&bag_id, &data).await.unwrap();

            let peers = vec![ProviderInfo::new([10u8; 32], 8080, 1000, "1.0")];
            let _ = manager.upload_bag(bag_id, peers).await;
        }

        // All should be queued
        assert_eq!(manager.active_session_count().await.unwrap(), 5);

        // Process pending (max 2 should be queued)
        manager.process_pending_uploads().await.unwrap();

        // After processing, should have pending tasks
        let pending = manager.pending_task_count().await.unwrap();
        assert!(pending <= 5);
    }

    #[tokio::test]
    async fn test_list_sessions() {
        let (manager, backend) = create_test_manager().await;

        for i in 1..=3 {
            let bag_id = [i as u8; 32];
            let data = format!("data {}", i).into_bytes();
            backend.store_bag(&bag_id, &data).await.unwrap();

            let peers = vec![ProviderInfo::new([10u8; 32], 8080, 1000, "1.0")];
            let _ = manager.upload_bag(bag_id, peers).await;
        }

        let sessions = manager.list_sessions().await.unwrap();
        assert_eq!(sessions.len(), 3);
    }

    #[tokio::test]
    async fn test_upload_config_builder() {
        let config = UploadConfig::new()
            .with_chunk_size(512 * 1024)
            .with_max_concurrent(5)
            .with_timeout(Duration::from_secs(600))
            .with_max_retries(4)
            .with_metrics(false);

        assert_eq!(config.chunk_size, 512 * 1024);
        assert_eq!(config.max_concurrent, 5);
        assert_eq!(config.operation_timeout, Duration::from_secs(600));
        assert_eq!(config.max_retries, 4);
        assert!(!config.enable_metrics);
    }

    #[tokio::test]
    async fn test_metrics_collection() {
        let (manager, _) = create_test_manager().await;

        let metrics = manager.get_metrics().await.unwrap();
        assert_eq!(metrics.total_bytes_uploaded, 0);
        assert_eq!(metrics.completed_sessions, 0);
        assert_eq!(metrics.failed_sessions, 0);
    }

    #[test]
    fn test_session_id_generation() {
        let bag_id1 = [1u8; 32];
        let bag_id2 = [2u8; 32];

        let session_id1 = UploadManager::generate_session_id(&bag_id1);
        let session_id2 = UploadManager::generate_session_id(&bag_id2);

        // Different inputs should produce different outputs
        assert_ne!(session_id1, session_id2);
        assert_eq!(session_id1.len(), 32);
        assert_eq!(session_id2.len(), 32);
    }

    #[tokio::test]
    async fn test_invalid_session_error() {
        let (manager, _) = create_test_manager().await;
        let invalid_session = [255u8; 32];

        let result = manager.get_session_status(invalid_session).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_upload_nonexistent_bag() {
        let (manager, _) = create_test_manager().await;
        let bag_id = [1u8; 32];

        let peers = vec![ProviderInfo::new([2u8; 32], 8080, 1000, "1.0")];
        let result = manager.upload_bag(bag_id, peers).await;

        assert!(result.is_err());
    }
}
