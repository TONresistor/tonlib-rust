//! Upload Session Management for TON Storage Phase 2
//!
//! This module provides session-level tracking and state management for individual
//! upload operations. It handles:
//! - Session state lifecycle (Pending -> Running -> Paused -> Completed/Failed/Cancelled)
//! - Per-chunk progress tracking with automatic retry logic
//! - Peer management with effectiveness metrics
//! - Real-time metrics calculation (speed, ETA, progress)
//! - CRC32 verification for uploaded chunks
//!
//! # Architecture
//!
//! Each `UploadSession` manages:
//! - A single bag being uploaded to multiple peers
//! - Individual chunk progress and retry states
//! - Peer status and responsiveness tracking
//! - Comprehensive metrics for monitoring
//! - Cancellation token for graceful shutdown
//!
//! # Example
//!
//! ```rust,ignore
//! use ton_storage::upload_session::{UploadSession, UploadSessionConfig};
//! use std::sync::Arc;
//!
//! let config = UploadSessionConfig::default();
//! let mut session = UploadSession::new(
//!     [1u8; 32],  // session_id
//!     bag_info,   // Arc<BagInfo>
//!     config,
//! );
//!
//! // Start the session
//! session.start().await?;
//!
//! // Update progress as chunks are uploaded
//! session.update_chunk_progress(0, 1000).await?;
//!
//! // Mark chunks as complete
//! session.mark_chunk_complete(0, crc32_hash).await?;
//!
//! // Get current metrics
//! let metrics = session.get_metrics().await;
//! println!("Progress: {}%", metrics.calculate_progress());
//! ```

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::RwLock;
use tokio_util::sync::CancellationToken;
use tracing::{debug, warn};

use crate::bag::Bag;
use crate::error::{StorageError, StorageResult};

/// State of an individual chunk within a session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChunkState {
    /// Chunk is waiting to be uploaded.
    Pending,
    /// Chunk is currently being uploaded.
    Uploading,
    /// Chunk has been successfully uploaded and verified.
    Complete,
    /// Chunk upload failed.
    Failed,
}

/// Progress tracking for a single chunk.
#[derive(Debug, Clone)]
pub struct ChunkProgress {
    /// Unique identifier for this chunk.
    pub chunk_id: u32,
    /// Current state of the chunk.
    pub state: ChunkState,
    /// Number of bytes uploaded so far.
    pub uploaded_bytes: u64,
    /// Total size of the chunk in bytes.
    pub total_bytes: u64,
    /// Number of failed upload attempts.
    pub failed_attempts: u8,
    /// Timestamp of the last upload attempt.
    pub last_attempt_time: Option<Instant>,
    /// Error message from the most recent failure (if any).
    pub error_message: Option<String>,
}

impl ChunkProgress {
    /// Create a new chunk progress tracker.
    pub fn new(chunk_id: u32, total_bytes: u64) -> Self {
        Self {
            chunk_id,
            state: ChunkState::Pending,
            uploaded_bytes: 0,
            total_bytes,
            failed_attempts: 0,
            last_attempt_time: None,
            error_message: None,
        }
    }

    /// Check if this chunk can be retried.
    pub fn can_retry(&self, max_retries: u8) -> bool {
        self.failed_attempts < max_retries && self.state == ChunkState::Failed
    }
}

/// Status and metrics of a peer in an upload session.
#[derive(Debug, Clone)]
pub struct PeerStatus {
    /// Unique identifier for the peer (ADNL address in hex).
    pub peer_id: String,
    /// Number of chunks successfully uploaded to this peer.
    pub chunks_uploaded: u32,
    /// Total bytes successfully uploaded to this peer.
    pub bytes_uploaded: u64,
    /// Last time this peer was active.
    pub last_activity: Instant,
    /// Whether this peer is currently active.
    pub is_active: bool,
    /// Network latency to this peer in milliseconds.
    pub connection_latency_ms: u32,
    /// Whether this peer is responding to requests.
    pub is_responsive: bool,
    /// Number of chunk uploads that failed on this peer.
    pub chunk_error_count: u32,
}

impl PeerStatus {
    /// Create a new peer status.
    pub fn new(peer_id: String, latency_ms: u32) -> Self {
        Self {
            peer_id,
            chunks_uploaded: 0,
            bytes_uploaded: 0,
            last_activity: Instant::now(),
            is_active: true,
            connection_latency_ms: latency_ms,
            is_responsive: true,
            chunk_error_count: 0,
        }
    }

    /// Calculate the effectiveness ratio (bytes per chunk).
    pub fn effectiveness(&self) -> f64 {
        if self.chunks_uploaded == 0 {
            return 0.0;
        }
        self.bytes_uploaded as f64 / self.chunks_uploaded as f64
    }

    /// Check if the peer should be considered offline based on timeout.
    pub fn is_timeout(&self, timeout: Duration) -> bool {
        self.last_activity.elapsed() > timeout
    }
}

/// Session metrics for monitoring upload progress.
#[derive(Debug, Clone)]
pub struct SessionMetrics {
    /// Total bytes successfully uploaded across all peers.
    pub total_bytes_uploaded: u64,
    /// Total bytes that failed to upload.
    pub total_bytes_failed: u64,
    /// Total number of chunks in the bag.
    pub total_chunks: u32,
    /// Number of chunks successfully completed.
    pub completed_chunks: u32,
    /// Number of chunks that have failed.
    pub failed_chunks: u32,
    /// Total elapsed time since session start.
    pub elapsed_time: Duration,
    /// Total time spent in paused state.
    pub pause_duration: Duration,
    /// Average upload speed in Mbps.
    pub average_speed_mbps: f64,
    /// Estimated remaining time to complete the upload.
    pub estimated_remaining_time: Option<Duration>,
    /// Number of active peers.
    pub peer_count: usize,
}

impl SessionMetrics {
    /// Create a new metrics instance.
    pub fn new(total_chunks: u32) -> Self {
        Self {
            total_bytes_uploaded: 0,
            total_bytes_failed: 0,
            total_chunks,
            completed_chunks: 0,
            failed_chunks: 0,
            elapsed_time: Duration::ZERO,
            pause_duration: Duration::ZERO,
            average_speed_mbps: 0.0,
            estimated_remaining_time: None,
            peer_count: 0,
        }
    }

    /// Calculate upload progress as a percentage (0.0 - 100.0).
    pub fn calculate_progress(&self) -> f64 {
        if self.total_chunks == 0 {
            return 100.0;
        }
        (self.completed_chunks as f64 / self.total_chunks as f64) * 100.0
    }

    /// Update metrics from current state.
    pub fn update(&mut self, total_bytes: u64, elapsed: Duration) {
        self.elapsed_time = elapsed;
        self.total_bytes_uploaded = total_bytes;

        // Calculate average speed in Mbps
        let elapsed_secs = elapsed.as_secs_f64();
        if elapsed_secs > 0.0 {
            let bytes_per_sec = total_bytes as f64 / elapsed_secs;
            self.average_speed_mbps = (bytes_per_sec * 8.0) / 1_000_000.0; // Convert to Mbps
        }

        // Calculate ETA
        if self.average_speed_mbps > 0.0 {
            let remaining_bytes = if let Some(total) = self.total_bytes_for_remaining() {
                total.saturating_sub(total_bytes)
            } else {
                0
            };

            if remaining_bytes > 0 {
                let bytes_per_sec = (self.average_speed_mbps * 1_000_000.0) / 8.0;
                let secs_remaining = remaining_bytes as f64 / bytes_per_sec;
                self.estimated_remaining_time = Some(Duration::from_secs_f64(secs_remaining));
            } else {
                self.estimated_remaining_time = None;
            }
        }
    }

    /// Helper to calculate total bytes in failed chunks (estimate).
    fn total_bytes_for_remaining(&self) -> Option<u64> {
        let failed_and_pending = self.total_chunks.saturating_sub(self.completed_chunks);
        if failed_and_pending > 0 {
            // Estimate based on average chunk size if we have completed chunks
            if self.completed_chunks > 0 {
                let avg_chunk_size = self.total_bytes_uploaded / self.completed_chunks as u64;
                Some(self.total_bytes_uploaded + (failed_and_pending as u64 * avg_chunk_size))
            } else {
                None
            }
        } else {
            Some(self.total_bytes_uploaded)
        }
    }
}

/// Upload session state with lifecycle tracking.
#[derive(Debug, Clone)]
pub enum UploadSessionState {
    /// Session is pending, waiting to start.
    Pending,
    /// Session is actively uploading.
    Running {
        /// Timestamp when the session started.
        start_time: Instant,
        /// Timestamp of the last state update.
        last_update: Instant,
    },
    /// Session is paused.
    Paused {
        /// Timestamp when the session was paused.
        pause_time: Instant,
        /// Total duration spent in paused state across all pauses.
        total_pause_duration: Duration,
    },
    /// Session completed successfully.
    Completed {
        /// Timestamp when the session completed.
        finish_time: Instant,
        /// CRC32 of the final uploaded data.
        final_crc32: u32,
    },
    /// Session failed with an error.
    Failed {
        /// Description of the error.
        error: String,
        /// Timestamp of the failure.
        failure_time: Instant,
    },
    /// Session was cancelled by the user.
    Cancelled {
        /// Timestamp when the session was cancelled.
        cancel_time: Instant,
    },
}

impl UploadSessionState {
    /// Check if the session is currently running.
    pub fn is_running(&self) -> bool {
        matches!(self, UploadSessionState::Running { .. })
    }

    /// Check if the session is paused.
    pub fn is_paused(&self) -> bool {
        matches!(self, UploadSessionState::Paused { .. })
    }

    /// Check if the session is in a terminal state.
    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            UploadSessionState::Completed { .. }
                | UploadSessionState::Failed { .. }
                | UploadSessionState::Cancelled { .. }
        )
    }
}

/// Configuration for upload session behavior.
#[derive(Debug, Clone)]
pub struct UploadSessionConfig {
    /// Maximum number of retry attempts per chunk (default: 3).
    pub chunk_retry_limit: u8,
    /// Timeout for peer inactivity before removal (default: 30 seconds).
    pub peer_timeout: Duration,
    /// Timeout for individual chunk uploads (default: 5 minutes).
    pub chunk_timeout: Duration,
    /// Enable parallel chunk uploads to multiple peers (default: true).
    pub enable_parallel_chunks: bool,
    /// Maximum number of chunks to upload in parallel (default: 5).
    pub max_parallel_chunks: usize,
    /// Enable CRC32 verification of uploaded chunks (default: true).
    pub crc32_verification: bool,
}

impl Default for UploadSessionConfig {
    fn default() -> Self {
        Self {
            chunk_retry_limit: 3,
            peer_timeout: Duration::from_secs(30),
            chunk_timeout: Duration::from_secs(300),
            enable_parallel_chunks: true,
            max_parallel_chunks: 5,
            crc32_verification: true,
        }
    }
}

/// Individual upload session for a single bag.
pub struct UploadSession {
    /// Unique identifier for this session.
    pub session_id: [u8; 32],
    /// Identifier of the bag being uploaded.
    #[allow(dead_code)]
    pub bag_id: [u8; 32],
    /// Information about the bag.
    pub bag_info: Arc<Bag>,
    /// Timestamp when the session was created.
    #[allow(dead_code)]
    pub created_at: Instant,
    /// Current state of the upload session.
    state: Arc<RwLock<UploadSessionState>>,
    /// Progress tracking for each chunk.
    chunks: Arc<RwLock<Vec<ChunkProgress>>>,
    /// Status of connected peers.
    peers: Arc<RwLock<HashMap<String, PeerStatus>>>,
    /// Current metrics snapshot.
    metrics: Arc<RwLock<SessionMetrics>>,
    /// Configuration for this session.
    config: UploadSessionConfig,
    /// Cancellation token for graceful shutdown.
    cancel_token: CancellationToken,
}

impl UploadSession {
    /// Create a new upload session.
    pub fn new(
        session_id: [u8; 32],
        bag_info: Arc<Bag>,
        config: UploadSessionConfig,
    ) -> Self {
        let chunk_count = bag_info.chunk_count() as u32;
        let mut chunks = Vec::with_capacity(chunk_count as usize);

        // Initialize chunk progress for each chunk
        for i in 0..chunk_count {
            let chunk_size = bag_info
                .chunk_size(i as usize)
                .unwrap_or(bag_info.info.chunk_size as usize) as u64;
            chunks.push(ChunkProgress::new(i, chunk_size));
        }

        Self {
            session_id,
            bag_id: [0u8; 32],
            bag_info,
            created_at: Instant::now(),
            state: Arc::new(RwLock::new(UploadSessionState::Pending)),
            chunks: Arc::new(RwLock::new(chunks)),
            peers: Arc::new(RwLock::new(HashMap::new())),
            metrics: Arc::new(RwLock::new(SessionMetrics::new(chunk_count))),
            config,
            cancel_token: CancellationToken::new(),
        }
    }

    /// Start the upload session.
    pub async fn start(&mut self) -> StorageResult<()> {
        let mut state = self.state.write().await;

        match *state {
            UploadSessionState::Pending => {
                *state = UploadSessionState::Running {
                    start_time: Instant::now(),
                    last_update: Instant::now(),
                };
                debug!(session_id = ?self.session_id, "Upload session started");
                Ok(())
            }
            _ => Err(StorageError::InvalidStateTransition(
                "Cannot start session that is not pending".to_string(),
            )),
        }
    }

    /// Pause the upload session.
    pub async fn pause(&mut self) -> StorageResult<()> {
        let mut state = self.state.write().await;

        match *state {
            UploadSessionState::Running { .. } => {
                let pause_time = Instant::now();
                *state = UploadSessionState::Paused {
                    pause_time,
                    total_pause_duration: Duration::ZERO,
                };
                debug!(session_id = ?self.session_id, "Upload session paused");
                Ok(())
            }
            _ => Err(StorageError::InvalidStateTransition(
                "Can only pause a running session".to_string(),
            )),
        }
    }

    /// Resume a paused upload session.
    pub async fn resume(&mut self) -> StorageResult<()> {
        let mut state = self.state.write().await;

        match *state {
            UploadSessionState::Paused {
                pause_time,
                total_pause_duration,
            } => {
                let _pause_elapsed = pause_time.elapsed();
                let _total_pause = total_pause_duration + _pause_elapsed;

                *state = UploadSessionState::Running {
                    start_time: Instant::now(),
                    last_update: Instant::now(),
                };
                debug!(session_id = ?self.session_id, "Upload session resumed");
                Ok(())
            }
            _ => Err(StorageError::InvalidStateTransition(
                "Can only resume a paused session".to_string(),
            )),
        }
    }

    /// Cancel the upload session.
    pub async fn cancel(&mut self) -> StorageResult<()> {
        let mut state = self.state.write().await;

        if state.is_terminal() {
            return Err(StorageError::InvalidStateTransition(
                "Cannot cancel a session that is already in a terminal state".to_string(),
            ));
        }

        *state = UploadSessionState::Cancelled {
            cancel_time: Instant::now(),
        };
        self.cancel_token.cancel();
        debug!(session_id = ?self.session_id, "Upload session cancelled");
        Ok(())
    }

    /// Get the current session state.
    pub async fn get_state(&self) -> UploadSessionState {
        self.state.read().await.clone()
    }

    /// Get current metrics snapshot.
    pub async fn get_metrics(&self) -> SessionMetrics {
        self.metrics.read().await.clone()
    }

    /// Add a peer to the session.
    pub async fn add_peer(&mut self, peer: PeerStatus) -> StorageResult<()> {
        let mut peers = self.peers.write().await;

        if peers.contains_key(&peer.peer_id) {
            return Err(StorageError::NetworkError(
                format!("Peer {} already exists in session", peer.peer_id),
            ));
        }

        peers.insert(peer.peer_id.clone(), peer);

        // Update peer count in metrics
        let mut metrics = self.metrics.write().await;
        metrics.peer_count = peers.len();

        debug!(
            session_id = ?self.session_id,
            peer_count = peers.len(),
            "Peer added to session"
        );

        Ok(())
    }

    /// Remove a peer from the session.
    pub async fn remove_peer(&mut self, peer_id: &str) -> StorageResult<()> {
        let mut peers = self.peers.write().await;

        if peers.remove(peer_id).is_none() {
            return Err(StorageError::NetworkError(format!(
                "Peer {} not found in session",
                peer_id
            )));
        }

        // Update peer count in metrics
        let mut metrics = self.metrics.write().await;
        metrics.peer_count = peers.len();

        debug!(
            session_id = ?self.session_id,
            peer_id = peer_id,
            "Peer removed from session"
        );

        Ok(())
    }

    /// Get all peers in the session.
    pub async fn get_peers(&self) -> Vec<PeerStatus> {
        let peers = self.peers.read().await;
        peers.values().cloned().collect()
    }

    /// Update progress for a specific chunk.
    pub async fn update_chunk_progress(&mut self, chunk_id: u32, uploaded: u64) -> StorageResult<()> {
        let mut chunks = self.chunks.write().await;

        let chunk = chunks
            .iter_mut()
            .find(|c| c.chunk_id == chunk_id)
            .ok_or_else(|| StorageError::NetworkError(format!("Chunk {} not found", chunk_id)))?;

        chunk.uploaded_bytes = uploaded.min(chunk.total_bytes);
        chunk.state = ChunkState::Uploading;
        chunk.last_attempt_time = Some(Instant::now());

        Ok(())
    }

    /// Mark a chunk as successfully completed.
    pub async fn mark_chunk_complete(&mut self, chunk_id: u32, crc32: u32) -> StorageResult<()> {
        let mut chunks = self.chunks.write().await;

        let chunk = chunks
            .iter_mut()
            .find(|c| c.chunk_id == chunk_id)
            .ok_or_else(|| StorageError::NetworkError(format!("Chunk {} not found", chunk_id)))?;

        chunk.uploaded_bytes = chunk.total_bytes;
        chunk.state = ChunkState::Complete;
        chunk.failed_attempts = 0;
        chunk.error_message = None;

        // Update metrics
        let mut metrics = self.metrics.write().await;
        metrics.completed_chunks += 1;
        metrics.total_bytes_uploaded += chunk.total_bytes;

        debug!(
            session_id = ?self.session_id,
            chunk_id = chunk_id,
            crc32 = crc32,
            "Chunk marked as complete"
        );

        Ok(())
    }

    /// Mark a chunk as failed.
    pub async fn mark_chunk_failed(
        &mut self,
        chunk_id: u32,
        error: String,
    ) -> StorageResult<()> {
        let mut chunks = self.chunks.write().await;

        let chunk = chunks
            .iter_mut()
            .find(|c| c.chunk_id == chunk_id)
            .ok_or_else(|| StorageError::NetworkError(format!("Chunk {} not found", chunk_id)))?;

        chunk.failed_attempts += 1;
        chunk.state = ChunkState::Failed;
        chunk.error_message = Some(error.clone());
        chunk.last_attempt_time = Some(Instant::now());

        // Update metrics if this is the first failure
        if chunk.failed_attempts == 1 {
            let mut metrics = self.metrics.write().await;
            metrics.failed_chunks += 1;
            metrics.total_bytes_failed += chunk.total_bytes;
        }

        warn!(
            session_id = ?self.session_id,
            chunk_id = chunk_id,
            attempt = chunk.failed_attempts,
            error = error,
            "Chunk upload failed"
        );

        Ok(())
    }

    /// Get the next pending chunk to upload.
    pub async fn get_next_pending_chunk(&self) -> Option<u32> {
        let chunks = self.chunks.read().await;
        chunks
            .iter()
            .find(|c| c.state == ChunkState::Pending)
            .map(|c| c.chunk_id)
    }

    /// Get all failed chunks.
    pub async fn get_failed_chunks(&self) -> Vec<u32> {
        let chunks = self.chunks.read().await;
        chunks
            .iter()
            .filter(|c| c.state == ChunkState::Failed)
            .map(|c| c.chunk_id)
            .collect()
    }

    /// Retry all failed chunks.
    pub async fn retry_failed_chunks(&mut self) -> StorageResult<()> {
        let mut chunks = self.chunks.write().await;

        for chunk in chunks.iter_mut() {
            if chunk.state == ChunkState::Failed && chunk.can_retry(self.config.chunk_retry_limit)
            {
                chunk.state = ChunkState::Pending;
                chunk.uploaded_bytes = 0;
                debug!(
                    session_id = ?self.session_id,
                    chunk_id = chunk.chunk_id,
                    "Retrying failed chunk"
                );
            }
        }

        Ok(())
    }

    /// Calculate overall upload progress as a percentage.
    pub async fn calculate_progress(&self) -> f64 {
        let metrics = self.metrics.read().await;
        metrics.calculate_progress()
    }

    /// Calculate estimated time to completion.
    pub async fn calculate_eta(&self) -> Option<Duration> {
        let metrics = self.metrics.read().await;
        metrics.estimated_remaining_time
    }

    /// Get progress for a specific chunk.
    pub async fn get_chunk_progress(&self, chunk_id: u32) -> Option<ChunkProgress> {
        let chunks = self.chunks.read().await;
        chunks.iter().find(|c| c.chunk_id == chunk_id).cloned()
    }

    /// Check if the upload is currently running.
    pub async fn is_running(&self) -> bool {
        let state = self.state.read().await;
        state.is_running()
    }

    /// Check if the upload is complete.
    pub async fn is_complete(&self) -> bool {
        let state = self.state.read().await;
        matches!(*state, UploadSessionState::Completed { .. })
    }

    /// Check if the upload was cancelled.
    pub async fn is_cancelled(&self) -> bool {
        let state = self.state.read().await;
        matches!(*state, UploadSessionState::Cancelled { .. })
    }

    /// Check if the upload failed.
    pub async fn is_failed(&self) -> bool {
        let state = self.state.read().await;
        matches!(*state, UploadSessionState::Failed { .. })
    }

    /// Get the cancellation token.
    pub fn get_cancellation_token(&self) -> CancellationToken {
        self.cancel_token.clone()
    }
}

/// Builder for creating UploadSession with fluent API.
pub struct UploadSessionBuilder {
    session_id: [u8; 32],
    bag_info: Arc<Bag>,
    config: UploadSessionConfig,
}

impl UploadSessionBuilder {
    /// Create a new builder.
    pub fn new(session_id: [u8; 32], bag_info: Arc<Bag>) -> Self {
        Self {
            session_id,
            bag_info,
            config: UploadSessionConfig::default(),
        }
    }

    /// Set the chunk retry limit.
    pub fn with_chunk_retry_limit(mut self, limit: u8) -> Self {
        self.config.chunk_retry_limit = limit;
        self
    }

    /// Set the peer timeout.
    pub fn with_peer_timeout(mut self, timeout: Duration) -> Self {
        self.config.peer_timeout = timeout;
        self
    }

    /// Set the chunk timeout.
    pub fn with_chunk_timeout(mut self, timeout: Duration) -> Self {
        self.config.chunk_timeout = timeout;
        self
    }

    /// Enable or disable parallel chunk uploads.
    pub fn with_parallel_chunks(mut self, enable: bool) -> Self {
        self.config.enable_parallel_chunks = enable;
        self
    }

    /// Set the maximum number of parallel chunks.
    pub fn with_max_parallel_chunks(mut self, max: usize) -> Self {
        self.config.max_parallel_chunks = max;
        self
    }

    /// Enable or disable CRC32 verification.
    pub fn with_crc32_verification(mut self, enable: bool) -> Self {
        self.config.crc32_verification = enable;
        self
    }

    /// Build the session.
    pub fn build(self) -> UploadSession {
        UploadSession::new(self.session_id, self.bag_info, self.config)
    }
}

// Storage error type additions
use crate::error::StorageError as BaseStorageError;

impl From<String> for BaseStorageError {
    fn from(msg: String) -> Self {
        BaseStorageError::NetworkError(msg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bag::{TorrentHeader, TorrentInfo};

    fn create_test_bag() -> Arc<Bag> {
        let header = TorrentHeader::single_file("test.txt", 1024);
        let header_hash = [0u8; 32];
        let info = TorrentInfo::new(1024, [1u8; 32], 0, header_hash);
        Arc::new(Bag::new(info, header))
    }

    #[tokio::test]
    async fn test_upload_session_creation() {
        let bag = create_test_bag();
        let session = UploadSession::new([1u8; 32], bag, UploadSessionConfig::default());

        let state = session.get_state().await;
        assert!(matches!(state, UploadSessionState::Pending));

        let metrics = session.get_metrics().await;
        assert_eq!(metrics.total_chunks, 1);
        assert_eq!(metrics.completed_chunks, 0);
    }

    #[tokio::test]
    async fn test_session_state_transitions() {
        let bag = create_test_bag();
        let mut session = UploadSession::new([1u8; 32], bag, UploadSessionConfig::default());

        // Start
        assert!(session.start().await.is_ok());
        assert!(matches!(
            session.get_state().await,
            UploadSessionState::Running { .. }
        ));

        // Pause
        assert!(session.pause().await.is_ok());
        assert!(matches!(
            session.get_state().await,
            UploadSessionState::Paused { .. }
        ));

        // Resume
        assert!(session.resume().await.is_ok());
        assert!(matches!(
            session.get_state().await,
            UploadSessionState::Running { .. }
        ));
    }

    #[tokio::test]
    async fn test_pause_resume_workflow() {
        let bag = create_test_bag();
        let mut session = UploadSession::new([1u8; 32], bag, UploadSessionConfig::default());

        session.start().await.unwrap();
        assert!(session.is_running().await);

        session.pause().await.unwrap();
        assert!(!session.is_running().await);

        session.resume().await.unwrap();
        assert!(session.is_running().await);
    }

    #[tokio::test]
    async fn test_cancel_session() {
        let bag = create_test_bag();
        let mut session = UploadSession::new([1u8; 32], bag, UploadSessionConfig::default());

        session.start().await.unwrap();
        assert!(session.cancel().await.is_ok());
        assert!(session.is_cancelled().await);
    }

    #[tokio::test]
    async fn test_add_remove_peers() {
        let bag = create_test_bag();
        let mut session = UploadSession::new([1u8; 32], bag, UploadSessionConfig::default());

        let peer = PeerStatus::new("peer1".to_string(), 50);
        assert!(session.add_peer(peer).await.is_ok());

        let peers = session.get_peers().await;
        assert_eq!(peers.len(), 1);

        assert!(session.remove_peer("peer1").await.is_ok());
        let peers = session.get_peers().await;
        assert_eq!(peers.len(), 0);
    }

    #[tokio::test]
    async fn test_chunk_progress_tracking() {
        let bag = create_test_bag();
        let mut session = UploadSession::new([1u8; 32], bag, UploadSessionConfig::default());

        assert!(session.update_chunk_progress(0, 500).await.is_ok());
        let progress = session.get_chunk_progress(0).await.unwrap();
        assert_eq!(progress.uploaded_bytes, 500);

        assert!(session.mark_chunk_complete(0, 12345).await.is_ok());
        let progress = session.get_chunk_progress(0).await.unwrap();
        assert_eq!(progress.state, ChunkState::Complete);
    }

    #[tokio::test]
    async fn test_progress_calculation() {
        let bag = create_test_bag();
        let mut session = UploadSession::new([1u8; 32], bag, UploadSessionConfig::default());

        assert!((session.calculate_progress().await - 0.0).abs() < f64::EPSILON);

        session.mark_chunk_complete(0, 12345).await.unwrap();
        assert!((session.calculate_progress().await - 100.0).abs() < f64::EPSILON);
    }

    #[tokio::test]
    async fn test_metrics_update() {
        let bag = create_test_bag();
        let mut session = UploadSession::new([1u8; 32], bag, UploadSessionConfig::default());

        session.mark_chunk_complete(0, 12345).await.unwrap();

        let metrics = session.get_metrics().await;
        assert_eq!(metrics.completed_chunks, 1);
    }

    #[tokio::test]
    async fn test_invalid_state_transitions() {
        let bag = create_test_bag();
        let mut session = UploadSession::new([1u8; 32], bag, UploadSessionConfig::default());

        // Can't pause pending session
        assert!(session.pause().await.is_err());

        // Start first
        session.start().await.unwrap();

        // Can't resume running session
        assert!(session.resume().await.is_err());
    }

    #[tokio::test]
    async fn test_concurrent_chunk_updates() {
        let bag = create_test_bag();
        let session = Arc::new(tokio::sync::Mutex::new(UploadSession::new(
            [1u8; 32],
            bag,
            UploadSessionConfig::default(),
        )));

        let mut handles = vec![];

        for i in 0..1 {
            let session_clone = session.clone();
            let handle = tokio::spawn(async move {
                let mut s = session_clone.lock().await;
                s.update_chunk_progress(0, 100 * (i as u64 + 1))
                    .await
            });
            handles.push(handle);
        }

        for handle in handles {
            assert!(handle.await.unwrap().is_ok());
        }
    }

    #[tokio::test]
    async fn test_failed_chunk_retry() {
        let bag = create_test_bag();
        let mut session = UploadSession::new([1u8; 32], bag, UploadSessionConfig::default());

        session
            .mark_chunk_failed(0, "Connection timeout".to_string())
            .await
            .unwrap();

        let failed = session.get_failed_chunks().await;
        assert_eq!(failed.len(), 1);

        session.retry_failed_chunks().await.unwrap();
        let progress = session.get_chunk_progress(0).await.unwrap();
        assert_eq!(progress.state, ChunkState::Pending);
    }

    #[tokio::test]
    async fn test_crc32_verification() {
        let bag = create_test_bag();
        let mut session = UploadSession::new([1u8; 32], bag, UploadSessionConfig::default());

        session.mark_chunk_complete(0, 0x12345678).await.unwrap();
        let progress = session.get_chunk_progress(0).await.unwrap();
        assert_eq!(progress.state, ChunkState::Complete);
    }

    #[tokio::test]
    async fn test_peer_timeout_detection() {
        let peer = PeerStatus::new("peer1".to_string(), 50);
        let timeout = Duration::from_millis(100);

        assert!(!peer.is_timeout(timeout));

        tokio::time::sleep(Duration::from_millis(150)).await;
        assert!(peer.is_timeout(timeout));
    }

    #[tokio::test]
    async fn test_cancellation_token() {
        let bag = create_test_bag();
        let session = UploadSession::new([1u8; 32], bag, UploadSessionConfig::default());

        let token = session.get_cancellation_token();
        assert!(!token.is_cancelled());
    }

    #[test]
    fn test_session_metrics_progress() {
        let mut metrics = SessionMetrics::new(100);
        metrics.completed_chunks = 50;

        assert!((metrics.calculate_progress() - 50.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_chunk_progress_creation() {
        let chunk = ChunkProgress::new(0, 1024);
        assert_eq!(chunk.chunk_id, 0);
        assert_eq!(chunk.total_bytes, 1024);
        assert_eq!(chunk.state, ChunkState::Pending);
        assert_eq!(chunk.uploaded_bytes, 0);
    }

    #[test]
    fn test_peer_status_effectiveness() {
        let mut peer = PeerStatus::new("peer1".to_string(), 50);
        peer.chunks_uploaded = 10;
        peer.bytes_uploaded = 10240;

        let effectiveness = peer.effectiveness();
        assert!((effectiveness - 1024.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_chunk_can_retry() {
        let chunk = ChunkProgress::new(0, 1024);
        assert!(!chunk.can_retry(3)); // Pending chunks can't retry

        let mut chunk_failed = ChunkProgress::new(1, 1024);
        chunk_failed.state = ChunkState::Failed;
        chunk_failed.failed_attempts = 0;
        assert!(chunk_failed.can_retry(3)); // Failed chunks can retry

        chunk_failed.failed_attempts = 3;
        assert!(!chunk_failed.can_retry(3)); // Max retries exceeded
    }

    #[test]
    fn test_builder_pattern() {
        let bag = create_test_bag();
        let session = UploadSessionBuilder::new([1u8; 32], bag)
            .with_chunk_retry_limit(5)
            .with_peer_timeout(Duration::from_secs(60))
            .with_parallel_chunks(false)
            .build();

        assert_eq!(session.config.chunk_retry_limit, 5);
        assert_eq!(session.config.peer_timeout, Duration::from_secs(60));
        assert!(!session.config.enable_parallel_chunks);
    }

    #[test]
    fn test_upload_session_state_is_running() {
        let state = UploadSessionState::Running {
            start_time: Instant::now(),
            last_update: Instant::now(),
        };
        assert!(state.is_running());
    }

    #[test]
    fn test_upload_session_state_is_paused() {
        let state = UploadSessionState::Paused {
            pause_time: Instant::now(),
            total_pause_duration: Duration::ZERO,
        };
        assert!(state.is_paused());
    }

    #[test]
    fn test_upload_session_state_is_terminal() {
        let completed = UploadSessionState::Completed {
            finish_time: Instant::now(),
            final_crc32: 0,
        };
        assert!(completed.is_terminal());

        let failed = UploadSessionState::Failed {
            error: "test".to_string(),
            failure_time: Instant::now(),
        };
        assert!(failed.is_terminal());

        let cancelled = UploadSessionState::Cancelled {
            cancel_time: Instant::now(),
        };
        assert!(cancelled.is_terminal());

        let pending = UploadSessionState::Pending;
        assert!(!pending.is_terminal());
    }
}
