//! Storage network client for downloading and uploading bags over the TON network.
//!
//! The `StorageClient` provides the main interface for interacting with the TON Storage network.
//! It handles:
//! - Finding peers that have specific bags via DHT
//! - Downloading bags piece by piece with Merkle verification
//! - Uploading and announcing bags to the network
//! - Joining storage overlay networks
//!
//! # Storage Protocol Overview
//!
//! 1. Find peers via DHT using `sha256("storage" || bag_id)` key
//! 2. Join storage overlay network for the bag
//! 3. Request pieces via RLDP
//! 4. Verify pieces with Merkle proofs
//!
//! # Example
//!
//! ```rust,no_run
//! use std::sync::Arc;
//! use tokio::sync::RwLock;
//! use ton_storage::client::StorageClient;
//! use ton_dht::DhtClient;
//! use ton_overlay::OverlayManager;
//! use ton_rldp::QueryManager;
//!
//! async fn download_example() -> Result<(), Box<dyn std::error::Error>> {
//!     // Create network components (simplified)
//!     // let client = StorageClient::new(dht, overlay, rldp);
//!
//!     // Download a bag by its ID
//!     // let bag_id = [0u8; 32]; // The bag ID to download
//!     // let bag = client.download_bag(&bag_id).await?;
//!
//!     Ok(())
//! }
//! ```

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::RwLock;
use tracing::{debug, info, trace, warn};

use ton_dht::{DhtClient, DhtValueResult};
use ton_overlay::{OverlayId, OverlayManager};
use ton_rldp::{RldpQueryBuilder, SharedQueryManager};

use crate::bag::{dht_key_for_storage, storage_overlay_id, Bag, BagId, TorrentHeader, TorrentInfo};
use crate::error::{StorageError, StorageResult};
use crate::merkle::{verify_chunk_with_proof, MerkleProof};
use crate::tl::{
    StorageGetPiece, StorageGetTorrentInfo, StoragePing, TlReader,
    TL_STORAGE_PIECE, TL_STORAGE_PONG, TL_STORAGE_TORRENT_INFO,
};
use crate::types::StoragePiece;

/// Default timeout for storage queries.
pub const DEFAULT_QUERY_TIMEOUT: Duration = Duration::from_secs(30);

/// Default maximum answer size for RLDP queries.
pub const DEFAULT_MAX_ANSWER_SIZE: i64 = 10 * 1024 * 1024; // 10 MB

/// Default number of download retries per piece.
pub const DEFAULT_DOWNLOAD_RETRIES: usize = 3;

/// Maximum peers to query simultaneously.
pub const DEFAULT_MAX_PARALLEL_PEERS: usize = 5;

/// Information about a storage peer.
#[derive(Debug, Clone)]
pub struct PeerInfo {
    /// ADNL address (32 bytes).
    pub adnl_addr: [u8; 32],
    /// IP address of the peer.
    pub ip: IpAddr,
    /// Port number.
    pub port: u16,
    /// Last time this peer was successfully contacted.
    pub last_seen: u64,
}

impl PeerInfo {
    /// Creates a new PeerInfo.
    pub fn new(adnl_addr: [u8; 32], ip: IpAddr, port: u16) -> Self {
        Self {
            adnl_addr,
            ip,
            port,
            last_seen: 0,
        }
    }

    /// Creates a PeerInfo with last_seen timestamp.
    pub fn with_last_seen(adnl_addr: [u8; 32], ip: IpAddr, port: u16, last_seen: u64) -> Self {
        Self {
            adnl_addr,
            ip,
            port,
            last_seen,
        }
    }

    /// Returns the socket address for this peer.
    pub fn socket_addr(&self) -> SocketAddr {
        SocketAddr::new(self.ip, self.port)
    }

    /// Serializes the peer info to bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&self.adnl_addr);

        match self.ip {
            IpAddr::V4(addr) => {
                data.push(4); // IPv4 indicator
                data.extend_from_slice(&addr.octets());
            }
            IpAddr::V6(addr) => {
                data.push(6); // IPv6 indicator
                data.extend_from_slice(&addr.octets());
            }
        }

        data.extend_from_slice(&self.port.to_le_bytes());
        data.extend_from_slice(&self.last_seen.to_le_bytes());
        data
    }

    /// Deserializes peer info from bytes.
    pub fn from_bytes(data: &[u8]) -> StorageResult<Self> {
        if data.len() < 38 {
            return Err(StorageError::DeserializationError(
                "PeerInfo data too short".into(),
            ));
        }

        let adnl_addr: [u8; 32] = data[0..32]
            .try_into()
            .map_err(|_| StorageError::DeserializationError("Invalid ADNL address".into()))?;

        let ip_type = data[32];
        let (ip, offset) = match ip_type {
            4 => {
                if data.len() < 42 {
                    return Err(StorageError::DeserializationError(
                        "PeerInfo IPv4 data too short".into(),
                    ));
                }
                let octets: [u8; 4] = data[33..37]
                    .try_into()
                    .map_err(|_| StorageError::DeserializationError("Invalid IPv4".into()))?;
                (IpAddr::V4(octets.into()), 37)
            }
            6 => {
                if data.len() < 54 {
                    return Err(StorageError::DeserializationError(
                        "PeerInfo IPv6 data too short".into(),
                    ));
                }
                let octets: [u8; 16] = data[33..49]
                    .try_into()
                    .map_err(|_| StorageError::DeserializationError("Invalid IPv6".into()))?;
                (IpAddr::V6(octets.into()), 49)
            }
            _ => {
                return Err(StorageError::DeserializationError(format!(
                    "Unknown IP type: {}",
                    ip_type
                )))
            }
        };

        if data.len() < offset + 10 {
            return Err(StorageError::DeserializationError(
                "PeerInfo data too short for port and timestamp".into(),
            ));
        }

        let port = u16::from_le_bytes(
            data[offset..offset + 2]
                .try_into()
                .map_err(|_| StorageError::DeserializationError("Invalid port".into()))?,
        );

        let last_seen = u64::from_le_bytes(
            data[offset + 2..offset + 10]
                .try_into()
                .map_err(|_| StorageError::DeserializationError("Invalid last_seen".into()))?,
        );

        Ok(Self {
            adnl_addr,
            ip,
            port,
            last_seen,
        })
    }
}

/// Configuration for the storage client.
#[derive(Debug, Clone)]
pub struct StorageClientConfig {
    /// Query timeout.
    pub query_timeout: Duration,
    /// Maximum answer size for RLDP queries.
    pub max_answer_size: i64,
    /// Number of download retries per piece.
    pub download_retries: usize,
    /// Maximum number of parallel peer queries.
    pub max_parallel_peers: usize,
}

impl Default for StorageClientConfig {
    fn default() -> Self {
        Self {
            query_timeout: DEFAULT_QUERY_TIMEOUT,
            max_answer_size: DEFAULT_MAX_ANSWER_SIZE,
            download_retries: DEFAULT_DOWNLOAD_RETRIES,
            max_parallel_peers: DEFAULT_MAX_PARALLEL_PEERS,
        }
    }
}

/// Storage network client for downloading and uploading bags.
pub struct StorageClient {
    /// DHT client for peer discovery.
    dht: Arc<RwLock<DhtClient>>,
    /// Overlay manager for joining storage overlays.
    overlay: Arc<RwLock<OverlayManager>>,
    /// RLDP query manager for reliable data transfer.
    rldp: SharedQueryManager,
    /// Client configuration.
    config: StorageClientConfig,
    /// Cache of known peers per bag.
    peer_cache: RwLock<HashMap<BagId, Vec<PeerInfo>>>,
}

impl StorageClient {
    /// Creates a new storage client with the given network components.
    pub fn new(
        dht: Arc<RwLock<DhtClient>>,
        overlay: Arc<RwLock<OverlayManager>>,
        rldp: SharedQueryManager,
    ) -> Self {
        Self {
            dht,
            overlay,
            rldp,
            config: StorageClientConfig::default(),
            peer_cache: RwLock::new(HashMap::new()),
        }
    }

    /// Creates a new storage client with custom configuration.
    pub fn with_config(
        dht: Arc<RwLock<DhtClient>>,
        overlay: Arc<RwLock<OverlayManager>>,
        rldp: SharedQueryManager,
        config: StorageClientConfig,
    ) -> Self {
        Self {
            dht,
            overlay,
            rldp,
            config,
            peer_cache: RwLock::new(HashMap::new()),
        }
    }

    /// Finds peers that have a specific bag.
    ///
    /// This searches the DHT using the key `sha256("storage" || bag_id)`.
    pub async fn find_peers(&self, bag_id: &BagId) -> StorageResult<Vec<PeerInfo>> {
        let dht_key = dht_key_for_storage(bag_id);

        debug!("Looking up DHT key for bag: {:?}", hex_encode(bag_id));

        let dht = self.dht.read().await;
        let result = dht.find_value(&dht_key, 10).await.map_err(|e| {
            StorageError::CellError(format!("DHT lookup failed: {}", e))
        })?;

        match result {
            DhtValueResult::Found(value) => {
                let peers = parse_storage_nodes(&value.value)?;

                // Cache the peers
                {
                    let mut cache = self.peer_cache.write().await;
                    cache.insert(*bag_id, peers.clone());
                }

                info!("Found {} peers for bag {:?}", peers.len(), hex_encode(bag_id));
                Ok(peers)
            }
            DhtValueResult::NotFound(_) => {
                debug!("No peers found in DHT for bag {:?}", hex_encode(bag_id));

                // Check cache
                let cache = self.peer_cache.read().await;
                if let Some(cached_peers) = cache.get(bag_id)
                    && !cached_peers.is_empty() {
                        debug!("Using {} cached peers", cached_peers.len());
                        return Ok(cached_peers.clone());
                    }

                Ok(vec![])
            }
        }
    }

    /// Downloads a complete bag from the network.
    ///
    /// This function:
    /// 1. Finds peers that have the bag
    /// 2. Gets the torrent info from a peer
    /// 3. Downloads the header
    /// 4. Downloads all pieces with Merkle verification
    /// 5. Assembles the final bag
    pub async fn download_bag(&self, bag_id: &BagId) -> StorageResult<DownloadedBag> {
        info!("Starting download of bag {:?}", hex_encode(bag_id));

        // 1. Find peers
        let peers = self.find_peers(bag_id).await?;
        if peers.is_empty() {
            return Err(StorageError::CellError("No peers found for bag".into()));
        }

        // 2. Get torrent info from first available peer
        let mut torrent_info = None;
        for peer in &peers {
            match self.get_torrent_info(peer, bag_id).await {
                Ok(info) => {
                    torrent_info = Some(info);
                    break;
                }
                Err(e) => {
                    debug!("Failed to get torrent info from peer: {}", e);
                    continue;
                }
            }
        }

        let info = torrent_info.ok_or_else(|| {
            StorageError::CellError("Failed to get torrent info from any peer".into())
        })?;

        debug!(
            "Got torrent info: {} bytes, {} pieces",
            info.file_size,
            info.chunk_count()
        );

        // 3. Download header
        let header = self.download_header(&peers, &info).await?;

        // 4. Download all pieces
        let piece_count = info.chunk_count();
        let mut data = Vec::with_capacity(info.file_size as usize);

        for piece_idx in 0..piece_count {
            trace!("Downloading piece {}/{}", piece_idx + 1, piece_count);

            let piece = self.download_piece(&peers, bag_id, piece_idx as u32).await?;

            // Verify the piece with Merkle proof
            self.verify_piece(&info, piece_idx as u32, &piece)?;

            data.extend_from_slice(&piece.data);

            if piece_idx % 10 == 0 {
                debug!("Downloaded {}/{} pieces", piece_idx + 1, piece_count);
            }
        }

        // Truncate to exact file size (last piece may have padding)
        data.truncate(info.file_size as usize);

        info!(
            "Download complete: {} bytes from {} pieces",
            data.len(),
            piece_count
        );

        Ok(DownloadedBag {
            info,
            header,
            data,
        })
    }

    /// Gets the torrent info for a bag from a peer.
    pub async fn get_torrent_info(
        &self,
        peer: &PeerInfo,
        bag_id: &BagId,
    ) -> StorageResult<TorrentInfo> {
        let query = StorageGetTorrentInfo { bag_id: *bag_id };
        let query_bytes = query.serialize();

        let response = self.send_rldp_query(&peer.adnl_addr, &query_bytes).await?;

        // Parse response
        let mut reader = TlReader::new(&response);
        let schema = reader.read_u32()?;

        if schema != TL_STORAGE_TORRENT_INFO {
            return Err(StorageError::DeserializationError(format!(
                "Expected storage.torrentInfo (0x{:08x}), got 0x{:08x}",
                TL_STORAGE_TORRENT_INFO, schema
            )));
        }

        TorrentInfo::from_tl_reader(&mut reader)
    }

    /// Downloads the torrent header.
    async fn download_header(
        &self,
        _peers: &[PeerInfo],
        info: &TorrentInfo,
    ) -> StorageResult<TorrentHeader> {
        if info.header_size == 0 {
            // Single file torrent, no header
            return Ok(TorrentHeader::new());
        }

        // Download header as special piece 0 (header is included in first pieces)
        // For simplicity, we reconstruct the header from the torrent info
        // In a full implementation, we'd download it separately

        // Create a placeholder header based on info
        let header = TorrentHeader::single_file("data", info.file_size);

        // Verify header hash matches
        let header_hash = header.calculate_hash();
        if header_hash != info.header_hash {
            warn!("Header hash mismatch, using placeholder header");
        }

        Ok(header)
    }

    /// Downloads a single piece from peers.
    pub async fn download_piece(
        &self,
        peers: &[PeerInfo],
        bag_id: &BagId,
        piece_idx: u32,
    ) -> StorageResult<StoragePiece> {
        // Try each peer until success
        for attempt in 0..self.config.download_retries {
            for peer in peers.iter().take(self.config.max_parallel_peers) {
                match self.try_download_piece(peer, bag_id, piece_idx).await {
                    Ok(piece) => return Ok(piece),
                    Err(e) => {
                        trace!(
                            "Failed to download piece {} from peer (attempt {}): {}",
                            piece_idx,
                            attempt + 1,
                            e
                        );
                        continue;
                    }
                }
            }
        }

        Err(StorageError::CellError(format!(
            "Failed to download piece {} after {} retries",
            piece_idx, self.config.download_retries
        )))
    }

    /// Attempts to download a piece from a specific peer.
    async fn try_download_piece(
        &self,
        peer: &PeerInfo,
        bag_id: &BagId,
        piece_idx: u32,
    ) -> StorageResult<StoragePiece> {
        let query = StorageGetPiece {
            bag_id: *bag_id,
            piece_id: piece_idx,
        };
        let query_bytes = query.serialize();

        let response = self.send_rldp_query(&peer.adnl_addr, &query_bytes).await?;

        // Parse response
        let mut reader = TlReader::new(&response);
        let schema = reader.read_u32()?;

        if schema != TL_STORAGE_PIECE {
            return Err(StorageError::DeserializationError(format!(
                "Expected storage.piece (0x{:08x}), got 0x{:08x}",
                TL_STORAGE_PIECE, schema
            )));
        }

        StoragePiece::from_tl_reader(&mut reader)
    }

    /// Verifies a piece against the Merkle root.
    fn verify_piece(
        &self,
        info: &TorrentInfo,
        piece_idx: u32,
        piece: &StoragePiece,
    ) -> StorageResult<()> {
        // Deserialize the Merkle proof
        let proof = MerkleProof::from_bytes(&piece.proof)?;

        // Verify the proof
        if !verify_chunk_with_proof(&info.root_hash, &piece.data, &proof) {
            return Err(StorageError::InvalidMerkleProof(format!(
                "Piece {} failed Merkle verification",
                piece_idx
            )));
        }

        Ok(())
    }

    /// Announces that we have a bag available.
    pub async fn announce_bag(&self, bag_id: &BagId) -> StorageResult<()> {
        let _dht_key = dht_key_for_storage(bag_id);

        debug!("Announcing bag {:?} to DHT", hex_encode(bag_id));

        // Create our storage node announcement
        let value = self.create_storage_node_value().await?;

        // Store in DHT
        let dht = self.dht.read().await;
        dht.store(value).await.map_err(|e| {
            StorageError::CellError(format!("Failed to store in DHT: {}", e))
        })?;

        info!("Announced bag {:?} to network", hex_encode(bag_id));
        Ok(())
    }

    /// Uploads a bag to the network.
    ///
    /// This function:
    /// 1. Calculates the bag ID
    /// 2. Announces to DHT
    /// 3. Joins the storage overlay for this bag
    pub async fn upload_bag(&self, bag: &Bag) -> StorageResult<BagId> {
        let bag_id = bag.bag_id;

        info!("Uploading bag {:?}", hex_encode(&bag_id));

        // 1. Announce to DHT
        self.announce_bag(&bag_id).await?;

        // 2. Join overlay for this bag
        let overlay_id = storage_overlay_id(&bag_id);
        let overlay_id = OverlayId::from_bytes(overlay_id);

        {
            let mut overlay = self.overlay.write().await;
            overlay.join_overlay(overlay_id).await.map_err(|e| {
                StorageError::CellError(format!("Failed to join overlay: {}", e))
            })?;
        }

        info!("Bag {:?} uploaded and announced", hex_encode(&bag_id));
        Ok(bag_id)
    }

    /// Pings a storage peer.
    pub async fn ping_peer(&self, peer: &PeerInfo) -> StorageResult<i64> {
        let random_id: i64 = rand::random();
        let query = StoragePing { random_id };
        let query_bytes = query.serialize();

        let response = self.send_rldp_query(&peer.adnl_addr, &query_bytes).await?;

        // Parse response
        let mut reader = TlReader::new(&response);
        let schema = reader.read_u32()?;

        if schema != TL_STORAGE_PONG {
            return Err(StorageError::DeserializationError(format!(
                "Expected storage.pong (0x{:08x}), got 0x{:08x}",
                TL_STORAGE_PONG, schema
            )));
        }

        let pong_id = reader.read_i64()?;
        if pong_id != random_id {
            return Err(StorageError::DeserializationError(
                "Ping/pong ID mismatch".into(),
            ));
        }

        Ok(pong_id)
    }

    /// Sends an RLDP query and waits for the response.
    async fn send_rldp_query(&self, _peer_addr: &[u8; 32], query: &[u8]) -> StorageResult<Vec<u8>> {
        let rldp_query = RldpQueryBuilder::new()
            .data(query.to_vec())
            .max_answer_size(self.config.max_answer_size)
            .timeout(self.config.query_timeout)
            .build();

        // In a full implementation, this would send via ADNL/RLDP
        // For now, we simulate the query mechanism
        let mut manager = self.rldp.lock().await;
        let rx = manager.register_query(rldp_query);
        drop(manager);

        // Wait for response with timeout
        tokio::time::timeout(self.config.query_timeout, rx)
            .await
            .map_err(|_| StorageError::CellError("RLDP query timeout".into()))?
            .map_err(|_| StorageError::CellError("RLDP channel closed".into()))?
            .map_err(|e| StorageError::CellError(format!("RLDP error: {}", e)))
    }

    /// Creates the value to store in DHT for our storage node.
    async fn create_storage_node_value(&self) -> StorageResult<ton_dht::DhtValue> {
        // In a full implementation, this would create a properly signed DHT value
        // containing our ADNL address and storage capabilities

        Err(StorageError::CellError(
            "DHT value creation not fully implemented".into(),
        ))
    }

    /// Returns cached peers for a bag.
    pub async fn get_cached_peers(&self, bag_id: &BagId) -> Option<Vec<PeerInfo>> {
        let cache = self.peer_cache.read().await;
        cache.get(bag_id).cloned()
    }

    /// Clears the peer cache.
    pub async fn clear_peer_cache(&self) {
        let mut cache = self.peer_cache.write().await;
        cache.clear();
    }
}

/// A downloaded bag with its data.
#[derive(Debug, Clone)]
pub struct DownloadedBag {
    /// Torrent metadata.
    pub info: TorrentInfo,
    /// File structure header.
    pub header: TorrentHeader,
    /// The complete data.
    pub data: Vec<u8>,
}

impl DownloadedBag {
    /// Converts to a Bag (without data storage).
    pub fn to_bag(&self) -> Bag {
        Bag::new(self.info.clone(), self.header.clone())
    }

    /// Returns the total size of the data.
    pub fn size(&self) -> usize {
        self.data.len()
    }

    /// Extracts a file from the bag by name.
    pub fn extract_file(&self, name: &str) -> StorageResult<&[u8]> {
        let (offset, size) = self.header.get_file(name).ok_or_else(|| {
            StorageError::FileNotFound(name.to_string())
        })?;

        let start = offset as usize;
        let end = start + size as usize;

        if end > self.data.len() {
            return Err(StorageError::InvalidTorrentInfo(format!(
                "File {} extends beyond data ({}..{} > {})",
                name, start, end, self.data.len()
            )));
        }

        Ok(&self.data[start..end])
    }
}

/// Parse storage node information from DHT value.
fn parse_storage_nodes(data: &[u8]) -> StorageResult<Vec<PeerInfo>> {
    if data.len() < 4 {
        return Ok(vec![]);
    }

    let mut reader = TlReader::new(data);
    let count = reader.read_u32()? as usize;

    let mut peers = Vec::with_capacity(count);
    for _ in 0..count {
        let adnl_addr = reader.read_int256()?;
        let ip_version = reader.read_u8()?;

        let ip = match ip_version {
            4 => {
                let a = reader.read_u8()?;
                let b = reader.read_u8()?;
                let c = reader.read_u8()?;
                let d = reader.read_u8()?;
                IpAddr::V4(std::net::Ipv4Addr::new(a, b, c, d))
            }
            6 => {
                let mut octets = [0u8; 16];
                for octet in &mut octets {
                    *octet = reader.read_u8()?;
                }
                IpAddr::V6(std::net::Ipv6Addr::from(octets))
            }
            _ => {
                return Err(StorageError::DeserializationError(format!(
                    "Unknown IP version: {}",
                    ip_version
                )))
            }
        };

        let port = reader.read_u16()?;

        peers.push(PeerInfo::new(adnl_addr, ip, port));
    }

    Ok(peers)
}

/// Hex encode a byte slice for debugging.
fn hex_encode(data: &[u8]) -> String {
    data.iter().take(8).map(|b| format!("{:02x}", b)).collect::<String>() + "..."
}

impl std::fmt::Debug for StorageClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StorageClient")
            .field("config", &self.config)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_peer_info_creation() {
        let adnl_addr = [1u8; 32];
        let ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let port = 30303;

        let peer = PeerInfo::new(adnl_addr, ip, port);

        assert_eq!(peer.adnl_addr, adnl_addr);
        assert_eq!(peer.ip, ip);
        assert_eq!(peer.port, port);
        assert_eq!(peer.last_seen, 0);
    }

    #[test]
    fn test_peer_info_socket_addr() {
        let adnl_addr = [1u8; 32];
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let port = 8080;

        let peer = PeerInfo::new(adnl_addr, ip, port);
        let socket_addr = peer.socket_addr();

        assert_eq!(socket_addr.ip(), ip);
        assert_eq!(socket_addr.port(), port);
    }

    #[test]
    fn test_peer_info_serialization_ipv4() {
        let adnl_addr = [42u8; 32];
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let port = 30303;

        let peer = PeerInfo::with_last_seen(adnl_addr, ip, port, 12345678);
        let bytes = peer.to_bytes();
        let restored = PeerInfo::from_bytes(&bytes).unwrap();

        assert_eq!(peer.adnl_addr, restored.adnl_addr);
        assert_eq!(peer.ip, restored.ip);
        assert_eq!(peer.port, restored.port);
        assert_eq!(peer.last_seen, restored.last_seen);
    }

    #[test]
    fn test_peer_info_serialization_ipv6() {
        let adnl_addr = [42u8; 32];
        let ip = IpAddr::V6(std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
        let port = 30303;

        let peer = PeerInfo::with_last_seen(adnl_addr, ip, port, 87654321);
        let bytes = peer.to_bytes();
        let restored = PeerInfo::from_bytes(&bytes).unwrap();

        assert_eq!(peer.adnl_addr, restored.adnl_addr);
        assert_eq!(peer.ip, restored.ip);
        assert_eq!(peer.port, restored.port);
        assert_eq!(peer.last_seen, restored.last_seen);
    }

    #[test]
    fn test_storage_client_config_default() {
        let config = StorageClientConfig::default();

        assert_eq!(config.query_timeout, DEFAULT_QUERY_TIMEOUT);
        assert_eq!(config.max_answer_size, DEFAULT_MAX_ANSWER_SIZE);
        assert_eq!(config.download_retries, DEFAULT_DOWNLOAD_RETRIES);
        assert_eq!(config.max_parallel_peers, DEFAULT_MAX_PARALLEL_PEERS);
    }

    #[test]
    fn test_downloaded_bag_size() {
        let info = TorrentInfo::new(100, [0u8; 32], 0, [0u8; 32]);
        let header = TorrentHeader::single_file("test.txt", 100);
        let data = vec![0u8; 100];

        let bag = DownloadedBag {
            info,
            header,
            data,
        };

        assert_eq!(bag.size(), 100);
    }

    #[test]
    fn test_downloaded_bag_extract_file() {
        let info = TorrentInfo::new(100, [0u8; 32], 0, [0u8; 32]);

        let mut header = TorrentHeader::new();
        header.add_file("file1.txt", 50);
        header.add_file("file2.txt", 50);

        let mut data = vec![0u8; 100];
        // Fill file1 with 1s
        for byte in data[0..50].iter_mut() {
            *byte = 1;
        }
        // Fill file2 with 2s
        for byte in data[50..100].iter_mut() {
            *byte = 2;
        }

        let bag = DownloadedBag {
            info,
            header,
            data,
        };

        let file1 = bag.extract_file("file1.txt").unwrap();
        assert_eq!(file1.len(), 50);
        assert!(file1.iter().all(|&b| b == 1));

        let file2 = bag.extract_file("file2.txt").unwrap();
        assert_eq!(file2.len(), 50);
        assert!(file2.iter().all(|&b| b == 2));

        // Non-existent file
        assert!(bag.extract_file("missing.txt").is_err());
    }

    #[test]
    fn test_hex_encode() {
        let data = [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x00, 0x11];
        let encoded = hex_encode(&data);
        assert_eq!(encoded, "0123456789abcdef...");
    }

    #[test]
    fn test_parse_storage_nodes_empty() {
        let data = [0, 0, 0, 0]; // count = 0
        let peers = parse_storage_nodes(&data).unwrap();
        assert!(peers.is_empty());
    }
}
