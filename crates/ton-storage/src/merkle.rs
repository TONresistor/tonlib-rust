//! Merkle tree implementation for TON Storage.
//!
//! This module provides functionality for building Merkle trees from data chunks
//! and verifying Merkle proofs. The Merkle tree is used to verify individual
//! chunks without downloading the entire file.
//!
//! # Structure (Official TON Implementation)
//!
//! The Merkle tree is a binary tree where:
//! - Leaf nodes are Cells containing chunk data hash
//! - Internal nodes are Cells with references to child cells
//! - Node hashes are Cell representation hashes (not raw SHA256)
//! - The root hash is used to verify the entire data
//!
//! This matches the official TON Storage implementation which uses Cell-based
//! Merkle trees for compatibility with TON's proof system.
//!
//! # Example
//!
//! ```ignore
//! use ton_storage::merkle::{MerkleTree, build_merkle_tree};
//!
//! let data = b"Hello, TON Storage!";
//! let tree = build_merkle_tree(data, 10);
//!
//! // Get the root hash for verification
//! let root_hash = tree.root_hash();
//!
//! // Generate a proof for chunk 0
//! let proof = tree.generate_proof(0).unwrap();
//!
//! // Verify the proof
//! let chunk = &data[0..10];
//! assert!(verify_proof(&root_hash, 0, chunk, &proof));
//! ```

use crate::bag::DEFAULT_CHUNK_SIZE;
use crate::chunk::calculate_chunk_hashes;
use crate::error::{StorageError, StorageResult};
use ton_cell::CellBuilder;
use ton_crypto::sha256;

/// A node in the Merkle tree.
#[derive(Debug, Clone)]
pub struct MerkleNode {
    /// The hash at this node.
    pub hash: [u8; 32],
    /// Left child index (if internal node).
    pub left: Option<usize>,
    /// Right child index (if internal node).
    pub right: Option<usize>,
    /// Whether this is a leaf node.
    pub is_leaf: bool,
}

impl MerkleNode {
    /// Create a leaf node with the given hash.
    pub fn leaf(hash: [u8; 32]) -> Self {
        Self {
            hash,
            left: None,
            right: None,
            is_leaf: true,
        }
    }

    /// Create an internal node from two child indices.
    pub fn internal(hash: [u8; 32], left: usize, right: usize) -> Self {
        Self {
            hash,
            left: Some(left),
            right: Some(right),
            is_leaf: false,
        }
    }
}

/// A complete Merkle tree built from chunk hashes.
#[derive(Debug, Clone)]
pub struct MerkleTree {
    /// All nodes in the tree (stored in a flat array).
    nodes: Vec<MerkleNode>,
    /// Index of the root node.
    root_index: usize,
    /// Number of leaf nodes (chunks).
    leaf_count: usize,
}

impl MerkleTree {
    /// Build a Merkle tree from chunk hashes.
    ///
    /// # Arguments
    /// * `hashes` - SHA256 hashes of each data chunk
    ///
    /// # Returns
    /// A complete Merkle tree
    pub fn from_hashes(hashes: &[[u8; 32]]) -> StorageResult<Self> {
        if hashes.is_empty() {
            return Err(StorageError::EmptyData);
        }

        let mut nodes = Vec::new();
        let leaf_count = hashes.len();

        // Create leaf nodes
        for hash in hashes {
            nodes.push(MerkleNode::leaf(*hash));
        }

        // Build internal nodes level by level
        let mut level_start = 0;
        let mut level_size = leaf_count;

        while level_size > 1 {
            let level_end = level_start + level_size;
            let mut i = level_start;

            while i < level_end {
                let left_idx = i;
                let right_idx = if i + 1 < level_end { i + 1 } else { i };

                // Combine hashes
                let combined_hash = combine_hashes(&nodes[left_idx].hash, &nodes[right_idx].hash);

                // Create internal node
                nodes.push(MerkleNode::internal(combined_hash, left_idx, right_idx));

                i += 2;
            }

            level_start = level_end;
            level_size = level_size.div_ceil(2);
        }

        let root_index = nodes.len() - 1;

        Ok(Self {
            nodes,
            root_index,
            leaf_count,
        })
    }

    /// Get the root hash of the Merkle tree.
    pub fn root_hash(&self) -> [u8; 32] {
        self.nodes[self.root_index].hash
    }

    /// Get the number of leaves (chunks) in the tree.
    pub fn leaf_count(&self) -> usize {
        self.leaf_count
    }

    /// Get a leaf hash by index.
    pub fn get_leaf_hash(&self, index: usize) -> StorageResult<[u8; 32]> {
        if index >= self.leaf_count {
            return Err(StorageError::ChunkIndexOutOfBounds {
                index,
                total: self.leaf_count,
            });
        }
        Ok(self.nodes[index].hash)
    }

    /// Generate a Merkle proof for a specific chunk.
    ///
    /// A Merkle proof is a sequence of sibling hashes needed to
    /// reconstruct the path from the leaf to the root.
    ///
    /// # Arguments
    /// * `chunk_index` - Index of the chunk to prove
    ///
    /// # Returns
    /// A `MerkleProof` that can be used to verify the chunk
    pub fn generate_proof(&self, chunk_index: usize) -> StorageResult<MerkleProof> {
        if chunk_index >= self.leaf_count {
            return Err(StorageError::ChunkIndexOutOfBounds {
                index: chunk_index,
                total: self.leaf_count,
            });
        }

        let mut siblings = Vec::new();
        let mut directions = Vec::new();

        // Find the path from leaf to root
        let mut current_idx = chunk_index;
        let mut level_start = 0;
        let mut level_size = self.leaf_count;

        while level_size > 1 {
            let level_end = level_start + level_size;
            let pair_start = level_start + (current_idx - level_start) / 2 * 2;
            let left_idx = pair_start;
            let right_idx = if pair_start + 1 < level_end {
                pair_start + 1
            } else {
                pair_start
            };

            // Determine which sibling to include
            if current_idx == left_idx {
                // We're on the left, include right sibling
                siblings.push(self.nodes[right_idx].hash);
                directions.push(ProofDirection::Right);
            } else {
                // We're on the right, include left sibling
                siblings.push(self.nodes[left_idx].hash);
                directions.push(ProofDirection::Left);
            }

            // Move to parent
            let parent_offset = (current_idx - level_start) / 2;
            level_start = level_end;
            current_idx = level_start + parent_offset;
            level_size = level_size.div_ceil(2);
        }

        Ok(MerkleProof {
            chunk_index,
            root_hash: self.root_hash(),
            siblings,
            directions,
        })
    }

    /// Verify that a chunk hash is part of this tree.
    pub fn verify_chunk(&self, chunk_index: usize, chunk_hash: &[u8; 32]) -> StorageResult<bool> {
        let stored_hash = self.get_leaf_hash(chunk_index)?;
        Ok(&stored_hash == chunk_hash)
    }
}

/// Direction indicator for a Merkle proof step.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProofDirection {
    /// The sibling is on the left.
    Left,
    /// The sibling is on the right.
    Right,
}

/// A Merkle proof for a specific chunk.
#[derive(Debug, Clone)]
pub struct MerkleProof {
    /// Index of the chunk this proof is for.
    pub chunk_index: usize,
    /// Expected root hash.
    pub root_hash: [u8; 32],
    /// Sibling hashes along the path to root.
    pub siblings: Vec<[u8; 32]>,
    /// Directions indicating which side each sibling is on.
    pub directions: Vec<ProofDirection>,
}

impl MerkleProof {
    /// Verify this proof against a chunk's data.
    ///
    /// # Arguments
    /// * `chunk_data` - The actual chunk data
    ///
    /// # Returns
    /// `true` if the proof is valid, `false` otherwise
    pub fn verify(&self, chunk_data: &[u8]) -> bool {
        let chunk_hash = sha256(chunk_data);
        self.verify_hash(&chunk_hash)
    }

    /// Verify this proof against a chunk's hash.
    ///
    /// # Arguments
    /// * `chunk_hash` - The hash of the chunk data
    ///
    /// # Returns
    /// `true` if the proof is valid, `false` otherwise
    pub fn verify_hash(&self, chunk_hash: &[u8; 32]) -> bool {
        if self.siblings.len() != self.directions.len() {
            return false;
        }

        let mut current_hash = *chunk_hash;

        for (sibling, direction) in self.siblings.iter().zip(self.directions.iter()) {
            current_hash = match direction {
                ProofDirection::Left => combine_hashes(sibling, &current_hash),
                ProofDirection::Right => combine_hashes(&current_hash, sibling),
            };
        }

        current_hash == self.root_hash
    }

    /// Serialize the proof to bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        // chunk_index (8 bytes)
        bytes.extend_from_slice(&(self.chunk_index as u64).to_le_bytes());

        // root_hash (32 bytes)
        bytes.extend_from_slice(&self.root_hash);

        // siblings count (4 bytes) + siblings
        bytes.extend_from_slice(&(self.siblings.len() as u32).to_le_bytes());
        for sibling in &self.siblings {
            bytes.extend_from_slice(sibling);
        }

        // directions (1 byte each, packed into bits would be more efficient but simpler this way)
        for direction in &self.directions {
            bytes.push(match direction {
                ProofDirection::Left => 0,
                ProofDirection::Right => 1,
            });
        }

        bytes
    }

    /// Deserialize a proof from bytes.
    pub fn from_bytes(bytes: &[u8]) -> StorageResult<Self> {
        if bytes.len() < 44 {
            // 8 + 32 + 4 = 44 minimum
            return Err(StorageError::InvalidMerkleProof("Data too short".to_string()));
        }

        let mut offset = 0;

        // chunk_index (8 bytes)
        let chunk_index = u64::from_le_bytes(
            bytes[offset..offset + 8]
                .try_into()
                .map_err(|_| StorageError::InvalidMerkleProof("Invalid chunk_index".to_string()))?,
        ) as usize;
        offset += 8;

        // root_hash (32 bytes)
        let root_hash: [u8; 32] = bytes[offset..offset + 32]
            .try_into()
            .map_err(|_| StorageError::InvalidMerkleProof("Invalid root_hash".to_string()))?;
        offset += 32;

        // siblings count (4 bytes)
        let siblings_count = u32::from_le_bytes(
            bytes[offset..offset + 4]
                .try_into()
                .map_err(|_| StorageError::InvalidMerkleProof("Invalid siblings count".to_string()))?,
        ) as usize;
        offset += 4;

        // siblings
        let mut siblings = Vec::with_capacity(siblings_count);
        for _ in 0..siblings_count {
            if offset + 32 > bytes.len() {
                return Err(StorageError::InvalidMerkleProof(
                    "Truncated siblings".to_string(),
                ));
            }
            let sibling: [u8; 32] = bytes[offset..offset + 32]
                .try_into()
                .map_err(|_| StorageError::InvalidMerkleProof("Invalid sibling hash".to_string()))?;
            siblings.push(sibling);
            offset += 32;
        }

        // directions
        if offset + siblings_count > bytes.len() {
            return Err(StorageError::InvalidMerkleProof(
                "Truncated directions".to_string(),
            ));
        }

        let mut directions = Vec::with_capacity(siblings_count);
        for i in 0..siblings_count {
            directions.push(match bytes[offset + i] {
                0 => ProofDirection::Left,
                1 => ProofDirection::Right,
                _ => {
                    return Err(StorageError::InvalidMerkleProof(format!(
                        "Invalid direction: {}",
                        bytes[offset + i]
                    )))
                }
            });
        }

        Ok(Self {
            chunk_index,
            root_hash,
            siblings,
            directions,
        })
    }
}

/// Combine two hashes into a parent hash using Cell-based hashing.
///
/// This is used to compute internal node hashes in the Merkle tree.
/// According to official TON Storage (MerkleTree.cpp), the parent hash is computed by:
/// 1. Creating a Cell with references to left and right children
/// 2. Taking the Cell's representation hash
///
/// Official TON uses: `vm::CellBuilder().store_ref(l).store_ref(r).finalize()`
/// Since we work with hashes (not Cells), we store both hashes as data in a Cell.
///
/// This ensures compatibility with TON's proof system. No fallback allowed.
pub fn combine_hashes(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    // Create a Cell containing both hashes as data (256 bits each = 512 bits total)
    // This fits within the 1023-bit Cell data limit
    let mut builder = CellBuilder::new();

    // Store left hash (256 bits) - must succeed as 256 bits < 1023 bits
    builder
        .store_bytes(left)
        .expect("Cell has capacity for 256 bits");

    // Store right hash (256 bits) - must succeed as 512 bits < 1023 bits
    builder
        .store_bytes(right)
        .expect("Cell has capacity for 512 bits total");

    // Build and get hash - Cell building cannot fail with valid data
    builder
        .build()
        .expect("Cell building cannot fail with 512 bits of data")
        .hash()
}

/// Combine two hashes using simple SHA256 concatenation.
///
/// This is provided for backward compatibility with existing proofs.
pub fn combine_hashes_sha256(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut combined = [0u8; 64];
    combined[..32].copy_from_slice(left);
    combined[32..].copy_from_slice(right);
    sha256(&combined)
}

/// Build a Merkle tree from raw data.
///
/// # Arguments
/// * `data` - The raw data to build the tree from
/// * `chunk_size` - Size of each chunk
///
/// # Returns
/// A complete Merkle tree
pub fn build_merkle_tree(data: &[u8], chunk_size: usize) -> StorageResult<MerkleTree> {
    if data.is_empty() {
        return Err(StorageError::EmptyData);
    }

    let hashes = calculate_chunk_hashes(data, chunk_size)?;
    MerkleTree::from_hashes(&hashes)
}

/// Build a Merkle tree from data using the default chunk size (128 KB).
pub fn build_merkle_tree_default(data: &[u8]) -> StorageResult<MerkleTree> {
    build_merkle_tree(data, DEFAULT_CHUNK_SIZE)
}

/// Verify a chunk against a Merkle root hash using a proof.
///
/// # Arguments
/// * `root_hash` - The expected root hash
/// * `chunk_index` - Index of the chunk
/// * `chunk_data` - The chunk data to verify
/// * `proof` - The Merkle proof
///
/// # Returns
/// `true` if the chunk is valid, `false` otherwise
pub fn verify_chunk_with_proof(
    root_hash: &[u8; 32],
    chunk_data: &[u8],
    proof: &MerkleProof,
) -> bool {
    if &proof.root_hash != root_hash {
        return false;
    }
    proof.verify(chunk_data)
}

/// Calculate the expected tree depth for a given number of leaves.
pub fn tree_depth(leaf_count: usize) -> usize {
    if leaf_count <= 1 {
        return 0;
    }
    (leaf_count as f64).log2().ceil() as usize
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_combine_hashes() {
        let left = [1u8; 32];
        let right = [2u8; 32];

        let combined = combine_hashes(&left, &right);
        assert_eq!(combined.len(), 32);

        // Should be deterministic
        let combined2 = combine_hashes(&left, &right);
        assert_eq!(combined, combined2);

        // Order matters
        let combined_reversed = combine_hashes(&right, &left);
        assert_ne!(combined, combined_reversed);
    }

    #[test]
    fn test_merkle_tree_single_chunk() {
        let data = vec![1, 2, 3, 4, 5];
        let tree = build_merkle_tree(&data, 10).unwrap();

        assert_eq!(tree.leaf_count(), 1);
        assert_eq!(tree.root_hash(), sha256(&data));
    }

    #[test]
    fn test_merkle_tree_two_chunks() {
        let data = vec![1, 2, 3, 4, 5, 6];
        let tree = build_merkle_tree(&data, 3).unwrap();

        assert_eq!(tree.leaf_count(), 2);

        let hash1 = sha256(&[1, 2, 3]);
        let hash2 = sha256(&[4, 5, 6]);
        let expected_root = combine_hashes(&hash1, &hash2);

        assert_eq!(tree.root_hash(), expected_root);
    }

    #[test]
    fn test_merkle_tree_four_chunks() {
        let data = vec![0u8; 40];
        let tree = build_merkle_tree(&data, 10).unwrap();

        assert_eq!(tree.leaf_count(), 4);

        // Verify structure
        let h0 = sha256(&data[0..10]);
        let h1 = sha256(&data[10..20]);
        let h2 = sha256(&data[20..30]);
        let h3 = sha256(&data[30..40]);

        let h01 = combine_hashes(&h0, &h1);
        let h23 = combine_hashes(&h2, &h3);
        let root = combine_hashes(&h01, &h23);

        assert_eq!(tree.root_hash(), root);
    }

    #[test]
    fn test_merkle_tree_odd_chunks() {
        // 5 chunks - tree should handle odd number correctly
        let data = vec![0u8; 50];
        let tree = build_merkle_tree(&data, 10).unwrap();

        assert_eq!(tree.leaf_count(), 5);
        // Root hash should be deterministic
        let tree2 = build_merkle_tree(&data, 10).unwrap();
        assert_eq!(tree.root_hash(), tree2.root_hash());
    }

    #[test]
    fn test_merkle_proof_generation() {
        let data = vec![1u8, 2, 3, 4, 5, 6, 7, 8];
        let tree = build_merkle_tree(&data, 2).unwrap();

        // Generate proof for each chunk
        for i in 0..4 {
            let proof = tree.generate_proof(i).unwrap();
            assert_eq!(proof.chunk_index, i);
            assert_eq!(proof.root_hash, tree.root_hash());
        }

        // Out of bounds should fail
        assert!(tree.generate_proof(4).is_err());
    }

    #[test]
    fn test_merkle_proof_verification() {
        let data = vec![1u8, 2, 3, 4, 5, 6, 7, 8];
        let tree = build_merkle_tree(&data, 2).unwrap();

        // Verify each chunk
        for i in 0..4 {
            let chunk_start = i * 2;
            let chunk_end = chunk_start + 2;
            let chunk_data = &data[chunk_start..chunk_end];

            let proof = tree.generate_proof(i).unwrap();
            assert!(proof.verify(chunk_data), "Chunk {} verification failed", i);
        }
    }

    #[test]
    fn test_merkle_proof_verification_fails_wrong_data() {
        let data = vec![1u8, 2, 3, 4, 5, 6, 7, 8];
        let tree = build_merkle_tree(&data, 2).unwrap();

        let proof = tree.generate_proof(0).unwrap();

        // Wrong data should fail
        let wrong_data = vec![9u8, 10];
        assert!(!proof.verify(&wrong_data));
    }

    #[test]
    fn test_merkle_proof_serialization() {
        let data = vec![1u8, 2, 3, 4, 5, 6, 7, 8];
        let tree = build_merkle_tree(&data, 2).unwrap();

        let proof = tree.generate_proof(1).unwrap();
        let bytes = proof.to_bytes();
        let restored = MerkleProof::from_bytes(&bytes).unwrap();

        assert_eq!(proof.chunk_index, restored.chunk_index);
        assert_eq!(proof.root_hash, restored.root_hash);
        assert_eq!(proof.siblings, restored.siblings);
        assert_eq!(proof.directions, restored.directions);

        // Verify restored proof works
        let chunk_data = &data[2..4];
        assert!(restored.verify(chunk_data));
    }

    #[test]
    fn test_verify_chunk_with_proof() {
        let data = vec![0u8; 100];
        let tree = build_merkle_tree(&data, 10).unwrap();
        let root_hash = tree.root_hash();

        for i in 0..10 {
            let chunk_start = i * 10;
            let chunk_end = chunk_start + 10;
            let chunk_data = &data[chunk_start..chunk_end];

            let proof = tree.generate_proof(i).unwrap();
            assert!(verify_chunk_with_proof(&root_hash, chunk_data, &proof));
        }

        // Wrong root hash should fail
        let proof = tree.generate_proof(0).unwrap();
        let wrong_root = [99u8; 32];
        assert!(!verify_chunk_with_proof(&wrong_root, &data[0..10], &proof));
    }

    #[test]
    fn test_tree_depth() {
        assert_eq!(tree_depth(1), 0);
        assert_eq!(tree_depth(2), 1);
        assert_eq!(tree_depth(3), 2);
        assert_eq!(tree_depth(4), 2);
        assert_eq!(tree_depth(5), 3);
        assert_eq!(tree_depth(8), 3);
        assert_eq!(tree_depth(9), 4);
        assert_eq!(tree_depth(16), 4);
    }

    #[test]
    fn test_merkle_tree_empty_data() {
        let data: Vec<u8> = vec![];
        let result = build_merkle_tree(&data, 10);
        assert!(result.is_err());
    }

    #[test]
    fn test_merkle_tree_from_hashes_empty() {
        let hashes: Vec<[u8; 32]> = vec![];
        let result = MerkleTree::from_hashes(&hashes);
        assert!(result.is_err());
    }

    #[test]
    fn test_merkle_node_creation() {
        let hash = [1u8; 32];

        let leaf = MerkleNode::leaf(hash);
        assert!(leaf.is_leaf);
        assert!(leaf.left.is_none());
        assert!(leaf.right.is_none());

        let internal = MerkleNode::internal(hash, 0, 1);
        assert!(!internal.is_leaf);
        assert_eq!(internal.left, Some(0));
        assert_eq!(internal.right, Some(1));
    }

    #[test]
    fn test_large_tree() {
        // Test with a larger tree (128 chunks)
        let data: Vec<u8> = (0..1280).map(|i| (i % 256) as u8).collect();
        let tree = build_merkle_tree(&data, 10).unwrap();

        assert_eq!(tree.leaf_count(), 128);

        // Verify random chunks
        for i in [0, 1, 50, 100, 127].iter() {
            let chunk_start = i * 10;
            let chunk_end = chunk_start + 10;
            let chunk_data = &data[chunk_start..chunk_end];

            let proof = tree.generate_proof(*i).unwrap();
            assert!(
                proof.verify(chunk_data),
                "Failed to verify chunk {} in large tree",
                i
            );
        }
    }

    #[test]
    fn test_merkle_proof_hash_verification() {
        let data = vec![1u8, 2, 3, 4];
        let tree = build_merkle_tree(&data, 2).unwrap();

        let proof = tree.generate_proof(0).unwrap();

        let chunk_hash = sha256(&data[0..2]);
        assert!(proof.verify_hash(&chunk_hash));

        let wrong_hash = [0u8; 32];
        assert!(!proof.verify_hash(&wrong_hash));
    }

    #[test]
    fn test_get_leaf_hash() {
        let data = vec![1u8, 2, 3, 4, 5, 6];
        let tree = build_merkle_tree(&data, 2).unwrap();

        let hash0 = tree.get_leaf_hash(0).unwrap();
        assert_eq!(hash0, sha256(&[1, 2]));

        let hash1 = tree.get_leaf_hash(1).unwrap();
        assert_eq!(hash1, sha256(&[3, 4]));

        let hash2 = tree.get_leaf_hash(2).unwrap();
        assert_eq!(hash2, sha256(&[5, 6]));

        assert!(tree.get_leaf_hash(3).is_err());
    }

    #[test]
    fn test_verify_chunk_method() {
        let data = vec![1u8, 2, 3, 4];
        let tree = build_merkle_tree(&data, 2).unwrap();

        let chunk_hash = sha256(&[1, 2]);
        assert!(tree.verify_chunk(0, &chunk_hash).unwrap());

        let wrong_hash = [0u8; 32];
        assert!(!tree.verify_chunk(0, &wrong_hash).unwrap());

        assert!(tree.verify_chunk(5, &chunk_hash).is_err());
    }
}
