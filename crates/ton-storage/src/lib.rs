//! TON Storage Library
//!
//! This crate implements the TON Storage protocol, which is a decentralized
//! file storage system based on torrent-like technology with Merkle proofs.
//!
//! # Overview
//!
//! TON Storage allows distributing files across the TON network with:
//! - **Content-addressable storage**: Files are identified by their content hash (BagID)
//! - **Chunk-based transfer**: Files are split into 128 KB chunks
//! - **Merkle verification**: Each chunk can be independently verified
//! - **DHT-based discovery**: Peers are found via the TON DHT
//! - **Upload capability**: Full support for uploading and announcing bags (Phase 1)
//! - **Provider abstractions**: Pluggable storage backends for flexible deployment
//!
//! # Key Concepts
//!
//! | Concept | Description |
//! |---------|-------------|
//! | **Bag** | Collection of files (like a torrent) |
//! | **BagID** | SHA256 hash of torrent info cell |
//! | **Chunk** | 128 KB data block |
//! | **Merkle Tree** | SHA256 hashes of chunks in a binary tree |
//! | **StorageBackend** | Abstraction for persistent storage (in-memory, file-system, etc.) |
//!
//! # Modules
//!
//! - [`bag`]: Bag, BagID, TorrentInfo, and TorrentHeader structures
//! - [`chunk`]: Chunk management and splitting
//! - [`merkle`]: Merkle tree building and proof verification
//! - [`client`]: Network client for downloading and uploading bags
//! - [`provider`]: Storage backend abstractions and implementations
//! - [`tl`]: TL protocol structures and serialization
//! - [`types`]: Additional type definitions including provider state and bandwidth tracking
//! - [`error`]: Error types including upload, provider, and DHT signing errors
//! - [`dht_value`]: DHT value types for storage provider announcements (Phase 2)
//!
//! # Example: Local Operations
//!
//! ```
//! use ton_storage::{
//!     bag::{TorrentInfo, TorrentHeader, Bag, DEFAULT_CHUNK_SIZE},
//!     merkle::{build_merkle_tree, MerkleTree},
//!     chunk::{split_into_chunks, reassemble_chunks},
//! };
//!
//! // Create a bag from data
//! let data = b"Hello, TON Storage! This is some test data that will be chunked.";
//!
//! // Build the Merkle tree
//! let tree = build_merkle_tree(data, 16).unwrap();
//! let root_hash = tree.root_hash();
//!
//! // Create torrent info
//! let header = TorrentHeader::single_file("hello.txt", data.len() as u64);
//! let header_hash = header.calculate_hash();
//!
//! let mut info = TorrentInfo::new(
//!     data.len() as u64,
//!     root_hash,
//!     0,
//!     header_hash,
//! );
//! info = info.with_chunk_size(16).unwrap();
//!
//! // Calculate the BagID
//! let bag_id = info.calculate_bag_id();
//!
//! // Create the bag
//! let bag = Bag::new(info, header);
//!
//! // Split data into chunks
//! let chunks = split_into_chunks(data, 16).unwrap();
//!
//! // Generate and verify proofs for each chunk
//! for chunk in &chunks {
//!     let proof = tree.generate_proof(chunk.index).unwrap();
//!     assert!(proof.verify(&chunk.data));
//! }
//!
//! // Reassemble the data
//! let reassembled = reassemble_chunks(&chunks, data.len() as u64).unwrap();
//! assert_eq!(reassembled, data);
//! ```
//!
//! # Example: Network Operations
//!
//! ```rust,no_run
//! use std::sync::Arc;
//! use tokio::sync::RwLock;
//! use ton_storage::client::{StorageClient, DownloadedBag};
//!
//! async fn network_example() -> Result<(), Box<dyn std::error::Error>> {
//!     // Create network components (DHT, Overlay, RLDP)
//!     // let dht = Arc::new(RwLock::new(dht_client));
//!     // let overlay = Arc::new(RwLock::new(overlay_manager));
//!     // let rldp = ton_rldp::new_query_manager();
//!
//!     // Create storage client
//!     // let client = StorageClient::new(dht, overlay, rldp);
//!
//!     // Find peers for a bag
//!     // let bag_id = [0u8; 32]; // The bag ID to download
//!     // let peers = client.find_peers(&bag_id).await?;
//!
//!     // Download the bag
//!     // let bag = client.download_bag(&bag_id).await?;
//!
//!     // Extract a file from the bag
//!     // let file_data = bag.extract_file("readme.txt")?;
//!
//!     Ok(())
//! }
//! ```
//!
//! # Storage Protocol
//!
//! The TON Storage protocol works as follows:
//!
//! 1. **Peer Discovery**: Find peers via DHT using `sha256("storage" || bag_id)` key
//! 2. **Overlay Network**: Join storage overlay network for the specific bag
//! 3. **Piece Requests**: Request pieces via RLDP with Merkle proofs
//! 4. **Verification**: Verify each piece using its Merkle proof against the root hash

pub mod bag;
pub mod bag_creation;
pub mod chunk;
pub mod client;
pub mod dht_value;
pub mod error;
pub mod merkle;
pub mod provider;
pub mod provider_discovery;
pub mod tl;
pub mod types;
pub mod upload_manager;
pub mod upload_session;

// Re-export main types for convenience
pub use bag::{
    bag_id_from_hex, bag_id_to_hex, dht_key_for_storage, storage_overlay_id, Bag, BagId,
    TorrentHeader, TorrentInfo, DEFAULT_CHUNK_SIZE,
};
pub use chunk::{
    calculate_chunk_hashes, chunk_byte_range, chunk_count, reassemble_chunks, split_into_chunks,
    verify_chunk_hash, Chunk, ChunkIterator,
};
pub use client::{
    DownloadedBag, PeerInfo, StorageClient, StorageClientConfig,
    DEFAULT_DOWNLOAD_RETRIES, DEFAULT_MAX_ANSWER_SIZE, DEFAULT_MAX_PARALLEL_PEERS,
    DEFAULT_QUERY_TIMEOUT,
};
pub use error::{
    DhtSigningError, ProviderError, StorageError, StorageResult, UploadError,
};
pub use merkle::{
    build_merkle_tree, build_merkle_tree_default, combine_hashes, tree_depth,
    verify_chunk_with_proof, MerkleNode, MerkleProof, MerkleTree, ProofDirection,
};
pub use tl::{
    StorageGetPiece, StorageGetTorrentInfo, StoragePing, StoragePong, TlReader, TlWriter,
    TL_STORAGE_GET_PIECE, TL_STORAGE_GET_TORRENT_INFO, TL_STORAGE_PIECE, TL_STORAGE_PING,
    TL_STORAGE_PONG, TL_STORAGE_TORRENT_INFO,
    // Upload protocol types
    StorageAddress, StorageNodeInfo, StorageNodeValueTL, StorageUploadSessionInfo,
    StorageChunkUploadRequest, StorageChunkUploadResponse, StorageProviderListRequest,
    StorageProviderListResponse,
    // Upload protocol schema IDs
    TL_STORAGE_ADDRESS, TL_STORAGE_NODE_INFO, TL_STORAGE_NODE_VALUE,
    TL_STORAGE_UPLOAD_SESSION_INFO, TL_STORAGE_CHUNK_UPLOAD_REQUEST,
    TL_STORAGE_CHUNK_UPLOAD_RESPONSE, TL_STORAGE_PROVIDER_LIST_REQUEST,
    TL_STORAGE_PROVIDER_LIST_RESPONSE,
};
pub use provider::{
    BackendStats, FileSystemBackend, InMemoryBackend, PersistenceConfig, StorageBackend,
};
pub use provider_discovery::{
    DiscoveryConfig, PeerScore, PeerSelector, BagId as DiscoveryBagId,
};
pub use dht_value::{
    StorageNodeValue, StorageNodeValueSignature, StorageMetadata,
    StorageNodeValueBuilder,
};
pub use types::{
    BagStatus, BandwidthUsage, CreateTorrentParams, FileInfo, ProviderInfo, ProviderState,
    ReplicationPolicy, StoragePiece, TorrentFull, TorrentStatus, UploadSession,
};
pub use upload_manager::{
    UploadManager, UploadConfig, UploadMetrics, UploadSessionStatus, SessionState,
    DEFAULT_CHUNK_SIZE as UPLOAD_DEFAULT_CHUNK_SIZE, MAX_CONCURRENT_UPLOADS,
    UPLOAD_TIMEOUT, RETRY_ATTEMPTS, RETRY_BACKOFF_MS,
};
pub use upload_session::{
    UploadSessionBuilder, UploadSessionConfig, UploadSessionState,
    ChunkProgress, ChunkState, PeerStatus, SessionMetrics,
};
pub use bag_creation::{
    BagCreator, BagCreatorBuilder, BagCreationConfig, BagVerificationResult,
    ChunkVerificationDetails, BagCreationProgress,
    create_bag_from_file, create_bag_from_directory, create_bag_from_data,
    verify_bag_integrity, compute_file_hash, compute_directory_hash,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_full_workflow() {
        // Test a complete workflow: create bag, split chunks, build tree, verify
        let data = b"Hello, TON Storage! This is a test of the complete workflow.";
        let chunk_size = 16;

        // 1. Build Merkle tree
        let tree = build_merkle_tree(data, chunk_size).unwrap();
        let root_hash = tree.root_hash();

        // 2. Create torrent header
        let header = TorrentHeader::single_file("test.txt", data.len() as u64);
        let header_bytes = header.to_bytes();
        let header_hash = ton_crypto::sha256(&header_bytes);

        // 3. Create torrent info
        let info = TorrentInfo::new(
            data.len() as u64,
            root_hash,
            header_bytes.len() as u64,
            header_hash,
        )
        .with_chunk_size(chunk_size as u32)
        .unwrap()
        .with_description("Test bag");

        // 4. Calculate BagID
        let bag_id = info.calculate_bag_id();
        assert_eq!(bag_id.len(), 32);

        // 5. Create bag
        let bag = Bag::new(info, header);
        assert_eq!(bag.bag_id, bag_id);
        assert_eq!(bag.chunk_count(), tree.leaf_count());

        // 6. Split into chunks
        let chunks = split_into_chunks(data, chunk_size).unwrap();
        assert_eq!(chunks.len(), bag.chunk_count());

        // 7. Verify each chunk
        for chunk in &chunks {
            // Verify hash
            assert!(chunk.verify_hash());

            // Verify Merkle proof
            let proof = tree.generate_proof(chunk.index).unwrap();
            assert!(proof.verify(&chunk.data));
            assert!(verify_chunk_with_proof(&root_hash, &chunk.data, &proof));
        }

        // 8. Reassemble and verify
        let reassembled = reassemble_chunks(&chunks, data.len() as u64).unwrap();
        assert_eq!(reassembled.as_slice(), data);

        // 9. Verify DHT and overlay keys are deterministic
        let dht_key = dht_key_for_storage(&bag_id);
        let overlay_id = storage_overlay_id(&bag_id);
        assert_ne!(dht_key, overlay_id);
    }

    #[test]
    fn test_bag_id_round_trip() {
        let info = TorrentInfo::new(1024, [1u8; 32], 100, [2u8; 32])
            .with_description("Test");

        let bag_id = info.calculate_bag_id();
        let hex = bag_id_to_hex(&bag_id);
        let restored = bag_id_from_hex(&hex).unwrap();

        assert_eq!(bag_id, restored);
    }

    #[test]
    fn test_torrent_info_round_trip() {
        let info = TorrentInfo::new(1024 * 1024, [3u8; 32], 256, [4u8; 32])
            .with_chunk_size(64 * 1024)
            .unwrap()
            .with_description("Multi-MB test file");

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
    fn test_torrent_header_round_trip() {
        let mut header = TorrentHeader::new();
        header.add_file("file1.txt", 100);
        header.add_file("subdir/file2.txt", 200);
        header.add_file("subdir/file3.bin", 300);

        let bytes = header.to_bytes();
        let restored = TorrentHeader::from_bytes(&bytes).unwrap();

        assert_eq!(header.files_count, restored.files_count);
        assert_eq!(header.names, restored.names);
        assert_eq!(header.data_index, restored.data_index);
    }

    #[test]
    fn test_merkle_proof_round_trip() {
        let data = vec![0u8; 64];
        let tree = build_merkle_tree(&data, 8).unwrap();

        for i in 0..tree.leaf_count() {
            let proof = tree.generate_proof(i).unwrap();
            let bytes = proof.to_bytes();
            let restored = MerkleProof::from_bytes(&bytes).unwrap();

            assert_eq!(proof.chunk_index, restored.chunk_index);
            assert_eq!(proof.root_hash, restored.root_hash);
            assert_eq!(proof.siblings, restored.siblings);
            assert_eq!(proof.directions, restored.directions);

            // Verify restored proof works
            let chunk_start = i * 8;
            let chunk_data = &data[chunk_start..chunk_start + 8];
            assert!(restored.verify(chunk_data));
        }
    }

    #[test]
    fn test_chunk_count_calculation() {
        assert_eq!(chunk_count(0, DEFAULT_CHUNK_SIZE), 0);
        assert_eq!(chunk_count(1, DEFAULT_CHUNK_SIZE), 1);
        assert_eq!(chunk_count(DEFAULT_CHUNK_SIZE as u64, DEFAULT_CHUNK_SIZE), 1);
        assert_eq!(chunk_count(DEFAULT_CHUNK_SIZE as u64 + 1, DEFAULT_CHUNK_SIZE), 2);
        assert_eq!(chunk_count(DEFAULT_CHUNK_SIZE as u64 * 10, DEFAULT_CHUNK_SIZE), 10);
    }

    #[test]
    fn test_storage_piece() {
        let proof = vec![1, 2, 3];
        let data = vec![4, 5, 6, 7, 8];
        let piece = StoragePiece::new(proof.clone(), data.clone());

        assert_eq!(piece.proof, proof);
        assert_eq!(piece.data, data);
    }

    #[test]
    fn test_tree_depth_calculation() {
        assert_eq!(tree_depth(1), 0);
        assert_eq!(tree_depth(2), 1);
        assert_eq!(tree_depth(4), 2);
        assert_eq!(tree_depth(8), 3);
        assert_eq!(tree_depth(16), 4);
        assert_eq!(tree_depth(100), 7); // ceil(log2(100)) = 7
    }

    #[test]
    fn test_file_operations() {
        let mut header = TorrentHeader::new();
        header.add_file("readme.txt", 50);
        header.add_file("data.bin", 1000);
        header.add_file("images/logo.png", 500);

        let info = TorrentInfo::new(1550, [0u8; 32], 0, header.calculate_hash());
        let bag = Bag::new(info, header);

        // Get file info
        let (offset, size) = bag.get_file("readme.txt").unwrap();
        assert_eq!(offset, 0);
        assert_eq!(size, 50);

        let (offset, size) = bag.get_file("data.bin").unwrap();
        assert_eq!(offset, 50);
        assert_eq!(size, 1000);

        let (offset, size) = bag.get_file("images/logo.png").unwrap();
        assert_eq!(offset, 1050);
        assert_eq!(size, 500);

        // Non-existent file
        assert!(bag.get_file("missing.txt").is_err());
    }
}
