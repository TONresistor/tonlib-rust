//! TL (Type Language) structures for TON Storage.
//!
//! This module defines the TL structures used in the TON Storage protocol
//! for communication between storage nodes and clients, as well as types for
//! provider state management and bandwidth tracking.

use serde::{Deserialize, Serialize};
use std::time::Instant;

/// Represents a piece (chunk) with its Merkle proof and data.
///
/// Corresponds to TL: `storage.piece proof:bytes data:bytes = storage.Piece;`
#[derive(Debug, Clone)]
pub struct StoragePiece {
    /// Merkle proof for this piece (serialized as BoC).
    pub proof: Vec<u8>,
    /// The actual piece data.
    pub data: Vec<u8>,
}

impl StoragePiece {
    /// Create a new storage piece.
    pub fn new(proof: Vec<u8>, data: Vec<u8>) -> Self {
        Self { proof, data }
    }
}

/// Parameters for creating a new torrent.
///
/// Corresponds to TL: `storage.daemon.createTorrent path:string description:string
///                     allow_upload:Bool copy_inside:Bool upload_priority:int
///                     = storage.daemon.Torrent;`
#[derive(Debug, Clone)]
pub struct CreateTorrentParams {
    /// Path to the file or directory to create a torrent for.
    pub path: String,
    /// Optional description of the torrent.
    pub description: String,
    /// Whether to allow uploading this torrent to peers.
    pub allow_upload: bool,
    /// Whether to copy the file inside the storage daemon's directory.
    pub copy_inside: bool,
    /// Upload priority (higher = more likely to be uploaded).
    pub upload_priority: i32,
}

impl CreateTorrentParams {
    /// Create new torrent creation parameters.
    pub fn new(path: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            description: String::new(),
            allow_upload: true,
            copy_inside: false,
            upload_priority: 1,
        }
    }

    /// Set the description.
    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.description = description.into();
        self
    }

    /// Set whether to allow uploads.
    pub fn with_allow_upload(mut self, allow: bool) -> Self {
        self.allow_upload = allow;
        self
    }

    /// Set whether to copy inside.
    pub fn with_copy_inside(mut self, copy: bool) -> Self {
        self.copy_inside = copy;
        self
    }

    /// Set the upload priority.
    pub fn with_upload_priority(mut self, priority: i32) -> Self {
        self.upload_priority = priority;
        self
    }
}

impl Default for CreateTorrentParams {
    fn default() -> Self {
        Self::new("")
    }
}

/// Information about a single file within a torrent.
#[derive(Debug, Clone)]
pub struct FileInfo {
    /// Name of the file (relative path within the torrent).
    pub name: String,
    /// Size of the file in bytes.
    pub size: u64,
    /// Starting offset within the torrent data.
    pub offset: u64,
}

impl FileInfo {
    /// Create new file info.
    pub fn new(name: impl Into<String>, size: u64, offset: u64) -> Self {
        Self {
            name: name.into(),
            size,
            offset,
        }
    }
}

/// Torrent status information.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TorrentStatus {
    /// Torrent is being downloaded.
    Downloading,
    /// Torrent download is complete.
    Complete,
    /// Torrent is being seeded (uploaded to peers).
    Seeding,
    /// Torrent is paused.
    Paused,
    /// Torrent encountered an error.
    Error,
}

impl TorrentStatus {
    /// Check if the torrent is active (downloading or seeding).
    pub fn is_active(&self) -> bool {
        matches!(self, TorrentStatus::Downloading | TorrentStatus::Seeding)
    }

    /// Check if the torrent is complete.
    pub fn is_complete(&self) -> bool {
        matches!(self, TorrentStatus::Complete | TorrentStatus::Seeding)
    }
}

/// Full torrent information including download progress.
///
/// Corresponds to TL: `storage.daemon.getTorrentFull hash:int256 = storage.daemon.TorrentFull;`
#[derive(Debug, Clone)]
pub struct TorrentFull {
    /// The 32-byte BagID (hash of TorrentInfo).
    pub bag_id: [u8; 32],
    /// Total size in bytes.
    pub total_size: u64,
    /// Downloaded size in bytes.
    pub downloaded_size: u64,
    /// Root hash of the Merkle tree.
    pub root_hash: [u8; 32],
    /// Number of active peers.
    pub active_peers: u32,
    /// Download speed in bytes per second.
    pub download_speed: u64,
    /// Upload speed in bytes per second.
    pub upload_speed: u64,
    /// Current status.
    pub status: TorrentStatus,
    /// Description of the torrent.
    pub description: String,
    /// List of files in the torrent.
    pub files: Vec<FileInfo>,
}

impl TorrentFull {
    /// Calculate download progress as a percentage (0.0 - 100.0).
    pub fn progress(&self) -> f64 {
        if self.total_size == 0 {
            return 100.0;
        }
        (self.downloaded_size as f64 / self.total_size as f64) * 100.0
    }
}

/// Information about a storage provider.
///
/// Describes the capabilities and status of a provider node in the TON Storage network.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderInfo {
    /// ADNL address of the provider (32 bytes).
    pub address: [u8; 32],

    /// Network port the provider listens on.
    pub port: u16,

    /// Bandwidth capacity in kilobits per second.
    pub bandwidth_kbps: u32,

    /// How long the provider has been online in seconds.
    pub uptime_seconds: u64,

    /// Number of bags currently stored by this provider.
    pub bags_count: u32,

    /// Version of the storage protocol implemented.
    pub version: String,
}

impl ProviderInfo {
    /// Create new provider information.
    pub fn new(
        address: [u8; 32],
        port: u16,
        bandwidth_kbps: u32,
        version: impl Into<String>,
    ) -> Self {
        Self {
            address,
            port,
            bandwidth_kbps,
            uptime_seconds: 0,
            bags_count: 0,
            version: version.into(),
        }
    }

    /// Set the uptime.
    pub fn with_uptime(mut self, uptime_seconds: u64) -> Self {
        self.uptime_seconds = uptime_seconds;
        self
    }

    /// Set the bags count.
    pub fn with_bags_count(mut self, count: u32) -> Self {
        self.bags_count = count;
        self
    }
}

/// Current state of a storage provider.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ProviderState {
    /// Provider is online and operational.
    Online,

    /// Provider is offline and not accepting requests.
    Offline,

    /// Provider is currently synchronizing data.
    Syncing,

    /// Provider encountered an error (state holds the reason).
    Error { reason: String },
}

impl ProviderState {
    /// Check if the provider is operational.
    pub fn is_operational(&self) -> bool {
        matches!(self, ProviderState::Online)
    }
}

/// Status of a bag being downloaded or stored.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BagStatus {
    /// Bag is currently being downloaded.
    Downloading {
        /// Progress from 0.0 (not started) to 1.0 (complete).
        progress: f32,
    },

    /// Bag download is complete.
    Complete,

    /// Bag is being seeded (shared with other peers).
    Seeding,

    /// Bag download is paused.
    Paused,

    /// Bag encountered an error during download.
    Error {
        /// Reason for the error.
        reason: String,
    },
}

impl BagStatus {
    /// Check if the bag is active (downloading or seeding).
    pub fn is_active(&self) -> bool {
        matches!(
            self,
            BagStatus::Downloading { .. } | BagStatus::Seeding
        )
    }

    /// Check if the bag download is complete.
    pub fn is_complete(&self) -> bool {
        matches!(self, BagStatus::Complete | BagStatus::Seeding)
    }
}

/// Bandwidth usage statistics.
#[derive(Debug, Clone)]
pub struct BandwidthUsage {
    /// Current upload speed in kilobits per second.
    pub upload_kbps: u32,

    /// Current download speed in kilobits per second.
    pub download_kbps: u32,

    /// Total bytes uploaded so far.
    pub total_uploaded_bytes: u64,

    /// Total bytes downloaded so far.
    pub total_downloaded_bytes: u64,

    /// Last time statistics were updated.
    pub last_updated: Instant,
}

impl BandwidthUsage {
    /// Create new bandwidth usage statistics.
    pub fn new() -> Self {
        Self {
            upload_kbps: 0,
            download_kbps: 0,
            total_uploaded_bytes: 0,
            total_downloaded_bytes: 0,
            last_updated: Instant::now(),
        }
    }

    /// Update current bandwidth speeds.
    pub fn update(&mut self, upload_kbps: u32, download_kbps: u32) {
        self.upload_kbps = upload_kbps;
        self.download_kbps = download_kbps;
        self.last_updated = Instant::now();
    }

    /// Add uploaded bytes.
    pub fn add_uploaded(&mut self, bytes: u64) {
        self.total_uploaded_bytes += bytes;
    }

    /// Add downloaded bytes.
    pub fn add_downloaded(&mut self, bytes: u64) {
        self.total_downloaded_bytes += bytes;
    }
}

impl Default for BandwidthUsage {
    fn default() -> Self {
        Self::new()
    }
}

/// Policy for replicating bags across the network.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplicationPolicy {
    /// Minimum number of peers that should have this bag.
    pub min_peers: u32,

    /// Maximum number of peers to replicate to.
    pub max_peers: u32,

    /// Priority for replication (0-255, higher = more important).
    pub priority: u8,

    /// Whether to automatically replicate when below min_peers.
    pub auto_replicate: bool,
}

impl ReplicationPolicy {
    /// Create a new replication policy.
    pub fn new(min_peers: u32, max_peers: u32) -> Self {
        Self {
            min_peers,
            max_peers,
            priority: 128,
            auto_replicate: true,
        }
    }

    /// Set the priority level.
    pub fn with_priority(mut self, priority: u8) -> Self {
        self.priority = priority;
        self
    }

    /// Set whether to auto-replicate.
    pub fn with_auto_replicate(mut self, auto: bool) -> Self {
        self.auto_replicate = auto;
        self
    }
}

impl Default for ReplicationPolicy {
    fn default() -> Self {
        Self::new(3, 10)
    }
}

/// Represents an active upload session.
#[derive(Debug, Clone)]
pub struct UploadSession {
    /// The bag ID being uploaded.
    pub bag_id: [u8; 32],

    /// Total number of pieces in the bag.
    pub total_pieces: u32,

    /// Number of pieces successfully uploaded so far.
    pub uploaded_pieces: u32,

    /// When the upload started.
    pub start_time: Instant,

    /// List of peers this bag is being uploaded to.
    pub peer_list: Vec<[u8; 32]>,
}

impl UploadSession {
    /// Create a new upload session.
    pub fn new(bag_id: [u8; 32], total_pieces: u32) -> Self {
        Self {
            bag_id,
            total_pieces,
            uploaded_pieces: 0,
            start_time: Instant::now(),
            peer_list: Vec::new(),
        }
    }

    /// Get upload progress as a percentage.
    pub fn progress(&self) -> f32 {
        if self.total_pieces == 0 {
            return 100.0;
        }
        (self.uploaded_pieces as f32 / self.total_pieces as f32) * 100.0
    }

    /// Check if upload is complete.
    pub fn is_complete(&self) -> bool {
        self.uploaded_pieces >= self.total_pieces
    }

    /// Get elapsed time since upload started.
    pub fn elapsed(&self) -> std::time::Duration {
        self.start_time.elapsed()
    }

    /// Add a peer to the upload session.
    pub fn add_peer(&mut self, peer_addr: [u8; 32]) {
        if !self.peer_list.contains(&peer_addr) {
            self.peer_list.push(peer_addr);
        }
    }

    /// Update uploaded piece count.
    pub fn update_progress(&mut self, pieces: u32) {
        self.uploaded_pieces = std::cmp::min(pieces, self.total_pieces);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_storage_piece() {
        let piece = StoragePiece::new(vec![1, 2, 3], vec![4, 5, 6]);
        assert_eq!(piece.proof, vec![1, 2, 3]);
        assert_eq!(piece.data, vec![4, 5, 6]);
    }

    #[test]
    fn test_create_torrent_params_builder() {
        let params = CreateTorrentParams::new("/path/to/file")
            .with_description("Test torrent")
            .with_allow_upload(false)
            .with_copy_inside(true)
            .with_upload_priority(5);

        assert_eq!(params.path, "/path/to/file");
        assert_eq!(params.description, "Test torrent");
        assert!(!params.allow_upload);
        assert!(params.copy_inside);
        assert_eq!(params.upload_priority, 5);
    }

    #[test]
    fn test_file_info() {
        let info = FileInfo::new("test.txt", 1024, 0);
        assert_eq!(info.name, "test.txt");
        assert_eq!(info.size, 1024);
        assert_eq!(info.offset, 0);
    }

    #[test]
    fn test_torrent_status() {
        assert!(TorrentStatus::Downloading.is_active());
        assert!(TorrentStatus::Seeding.is_active());
        assert!(!TorrentStatus::Paused.is_active());

        assert!(TorrentStatus::Complete.is_complete());
        assert!(TorrentStatus::Seeding.is_complete());
        assert!(!TorrentStatus::Downloading.is_complete());
    }

    #[test]
    fn test_torrent_full_progress() {
        let torrent = TorrentFull {
            bag_id: [0u8; 32],
            total_size: 1000,
            downloaded_size: 500,
            root_hash: [0u8; 32],
            active_peers: 5,
            download_speed: 1024,
            upload_speed: 512,
            status: TorrentStatus::Downloading,
            description: "Test".to_string(),
            files: vec![],
        };

        assert!((torrent.progress() - 50.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_torrent_full_progress_empty() {
        let torrent = TorrentFull {
            bag_id: [0u8; 32],
            total_size: 0,
            downloaded_size: 0,
            root_hash: [0u8; 32],
            active_peers: 0,
            download_speed: 0,
            upload_speed: 0,
            status: TorrentStatus::Complete,
            description: "Empty".to_string(),
            files: vec![],
        };

        assert!((torrent.progress() - 100.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_provider_info_creation() {
        let info = ProviderInfo::new([1u8; 32], 8080, 1000, "1.0.0");
        assert_eq!(info.port, 8080);
        assert_eq!(info.bandwidth_kbps, 1000);
        assert_eq!(info.version, "1.0.0");
        assert_eq!(info.uptime_seconds, 0);
        assert_eq!(info.bags_count, 0);
    }

    #[test]
    fn test_provider_info_builder() {
        let info = ProviderInfo::new([1u8; 32], 8080, 1000, "1.0.0")
            .with_uptime(3600)
            .with_bags_count(42);

        assert_eq!(info.uptime_seconds, 3600);
        assert_eq!(info.bags_count, 42);
    }

    #[test]
    fn test_provider_state_operational() {
        assert!(ProviderState::Online.is_operational());
        assert!(!ProviderState::Offline.is_operational());
        assert!(!ProviderState::Syncing.is_operational());
    }

    #[test]
    fn test_bag_status_active() {
        assert!(BagStatus::Downloading { progress: 0.5 }.is_active());
        assert!(BagStatus::Seeding.is_active());
        assert!(!BagStatus::Paused.is_active());
        assert!(!BagStatus::Complete.is_active());
    }

    #[test]
    fn test_bag_status_complete() {
        assert!(!BagStatus::Downloading { progress: 0.9 }.is_complete());
        assert!(BagStatus::Complete.is_complete());
        assert!(BagStatus::Seeding.is_complete());
    }

    #[test]
    fn test_bandwidth_usage() {
        let mut usage = BandwidthUsage::new();
        assert_eq!(usage.upload_kbps, 0);
        assert_eq!(usage.download_kbps, 0);

        usage.update(1000, 2000);
        assert_eq!(usage.upload_kbps, 1000);
        assert_eq!(usage.download_kbps, 2000);

        usage.add_uploaded(1024);
        usage.add_downloaded(2048);
        assert_eq!(usage.total_uploaded_bytes, 1024);
        assert_eq!(usage.total_downloaded_bytes, 2048);
    }

    #[test]
    fn test_replication_policy_defaults() {
        let policy = ReplicationPolicy::default();
        assert_eq!(policy.min_peers, 3);
        assert_eq!(policy.max_peers, 10);
        assert_eq!(policy.priority, 128);
        assert!(policy.auto_replicate);
    }

    #[test]
    fn test_replication_policy_builder() {
        let policy = ReplicationPolicy::new(5, 20)
            .with_priority(200)
            .with_auto_replicate(false);

        assert_eq!(policy.min_peers, 5);
        assert_eq!(policy.max_peers, 20);
        assert_eq!(policy.priority, 200);
        assert!(!policy.auto_replicate);
    }

    #[test]
    fn test_upload_session_creation() {
        let session = UploadSession::new([1u8; 32], 100);
        assert_eq!(session.total_pieces, 100);
        assert_eq!(session.uploaded_pieces, 0);
        assert!(!session.is_complete());
    }

    #[test]
    fn test_upload_session_progress() {
        let mut session = UploadSession::new([1u8; 32], 100);
        assert_eq!(session.progress(), 0.0);

        session.update_progress(50);
        assert!((session.progress() - 50.0).abs() < f32::EPSILON);

        session.update_progress(100);
        assert!((session.progress() - 100.0).abs() < f32::EPSILON);
        assert!(session.is_complete());
    }

    #[test]
    fn test_upload_session_peers() {
        let mut session = UploadSession::new([1u8; 32], 100);
        let peer1 = [2u8; 32];
        let peer2 = [3u8; 32];

        session.add_peer(peer1);
        assert_eq!(session.peer_list.len(), 1);

        session.add_peer(peer2);
        assert_eq!(session.peer_list.len(), 2);

        // Adding duplicate should not increase count
        session.add_peer(peer1);
        assert_eq!(session.peer_list.len(), 2);
    }
}
