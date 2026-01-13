//! Overlay node management.
//!
//! This module provides types for representing and managing nodes in an overlay network.

use std::time::{SystemTime, UNIX_EPOCH};

use ton_crypto::{sha256, Ed25519Keypair, verify_signature};

use crate::error::{OverlayError, Result};
use crate::tl::{TlReader, TlWriter, OVERLAY_NODE, OVERLAY_NODE_TO_SIGN, OVERLAY_NODES, PUB_ED25519};

/// An overlay node - a participant in an overlay network.
#[derive(Debug, Clone)]
pub struct OverlayNode {
    /// The node's Ed25519 public key.
    pub id: [u8; 32],
    /// The overlay ID this node belongs to.
    pub overlay: [u8; 32],
    /// Version timestamp (Unix time).
    pub version: i32,
    /// Signature over the node data.
    pub signature: Vec<u8>,
}

impl OverlayNode {
    /// Creates a new overlay node.
    pub fn new(id: [u8; 32], overlay: [u8; 32], version: i32) -> Self {
        Self {
            id,
            overlay,
            version,
            signature: Vec::new(),
        }
    }

    /// Creates a new overlay node with the current version.
    pub fn with_current_version(id: [u8; 32], overlay: [u8; 32]) -> Self {
        let version = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i32;

        Self {
            id,
            overlay,
            version,
            signature: Vec::new(),
        }
    }

    /// Creates a new overlay node from a keypair.
    pub fn from_keypair(keypair: &Ed25519Keypair, overlay: [u8; 32]) -> Self {
        let mut node = Self::with_current_version(keypair.public_key, overlay);
        node.sign(keypair);
        node
    }

    /// Computes the node ID (hash of TL-serialized public key).
    pub fn node_id(&self) -> [u8; 32] {
        let mut writer = TlWriter::new();
        writer.write_u32(PUB_ED25519);
        writer.write_int256(&self.id);
        sha256(&writer.finish())
    }

    /// Computes the data to be signed.
    ///
    /// Uses `overlay.node.toSign` schema as per official TON:
    /// `overlay.node.toSign id:adnl.id.short overlay:int256 version:int = overlay.Node.ToSign`
    ///
    /// Note: `id` is the ADNL short ID (SHA256 of TL-serialized public key), not the raw public key.
    fn compute_sign_data(&self) -> Vec<u8> {
        // Compute ADNL short ID = SHA256(TL-serialized public key)
        let adnl_short_id = self.node_id();

        let mut writer = TlWriter::new();
        writer.write_u32(OVERLAY_NODE_TO_SIGN);
        writer.write_int256(&adnl_short_id);
        writer.write_int256(&self.overlay);
        writer.write_i32(self.version);
        writer.finish()
    }

    /// Signs the node data with the given keypair.
    pub fn sign(&mut self, keypair: &Ed25519Keypair) {
        let data = self.compute_sign_data();
        self.signature = keypair.sign(&data).to_vec();
    }

    /// Verifies the node's signature.
    pub fn verify_signature(&self) -> Result<()> {
        if self.signature.len() != 64 {
            return Err(OverlayError::SignatureVerificationFailed(
                "invalid signature length".into(),
            ));
        }

        let data = self.compute_sign_data();
        let sig: [u8; 64] = self.signature.as_slice().try_into().map_err(|_| {
            OverlayError::SignatureVerificationFailed("invalid signature".into())
        })?;

        verify_signature(&self.id, &data, &sig).map_err(|e| {
            OverlayError::SignatureVerificationFailed(format!("signature verification failed: {}", e))
        })?;

        Ok(())
    }

    /// Checks if the node version is recent.
    pub fn is_recent(&self, max_age_secs: i32) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i32;

        self.version >= now - max_age_secs
    }

    /// Serializes the node to TL format.
    pub fn to_tl(&self) -> Vec<u8> {
        let mut writer = TlWriter::new();
        self.write_to(&mut writer);
        writer.finish()
    }

    /// Writes the node to a TL writer.
    pub fn write_to(&self, writer: &mut TlWriter) {
        writer.write_u32(OVERLAY_NODE);
        writer.write_u32(PUB_ED25519);
        writer.write_int256(&self.id);
        writer.write_int256(&self.overlay);
        writer.write_i32(self.version);
        writer.write_bytes(&self.signature);
    }

    /// Parses a node from TL format.
    pub fn from_tl(data: &[u8]) -> Result<Self> {
        let mut reader = TlReader::new(data);
        Self::read_from(&mut reader)
    }

    /// Reads a node from a TL reader.
    pub fn read_from(reader: &mut TlReader) -> Result<Self> {
        let schema = reader.read_u32()?;
        if schema != OVERLAY_NODE {
            return Err(OverlayError::TlError(format!(
                "expected overlay.node (0x{:08x}), got 0x{:08x}",
                OVERLAY_NODE, schema
            )));
        }

        // Read public key
        let key_type = reader.read_u32()?;
        if key_type != PUB_ED25519 {
            return Err(OverlayError::TlError(format!(
                "expected pub.ed25519 (0x{:08x}), got 0x{:08x}",
                PUB_ED25519, key_type
            )));
        }

        let id = reader.read_int256()?;
        let overlay = reader.read_int256()?;
        let version = reader.read_i32()?;
        let signature = reader.read_bytes()?;

        Ok(Self {
            id,
            overlay,
            version,
            signature,
        })
    }
}

impl PartialEq for OverlayNode {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id && self.overlay == other.overlay
    }
}

impl Eq for OverlayNode {}

impl std::hash::Hash for OverlayNode {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.id.hash(state);
        self.overlay.hash(state);
    }
}

/// A collection of overlay nodes.
#[derive(Debug, Clone, Default)]
pub struct OverlayNodes {
    /// The nodes in this collection.
    pub nodes: Vec<OverlayNode>,
}

impl OverlayNodes {
    /// Creates an empty node collection.
    pub fn new() -> Self {
        Self { nodes: Vec::new() }
    }

    /// Creates a node collection with the given nodes.
    pub fn with_nodes(nodes: Vec<OverlayNode>) -> Self {
        Self { nodes }
    }

    /// Adds a node to the collection.
    pub fn add(&mut self, node: OverlayNode) {
        // Check for duplicates
        if !self.nodes.iter().any(|n| n.id == node.id) {
            self.nodes.push(node);
        }
    }

    /// Returns the number of nodes.
    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    /// Returns true if the collection is empty.
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    /// Returns an iterator over the nodes.
    pub fn iter(&self) -> impl Iterator<Item = &OverlayNode> {
        self.nodes.iter()
    }

    /// Serializes the nodes to TL format.
    pub fn to_tl(&self) -> Vec<u8> {
        let mut writer = TlWriter::new();
        self.write_to(&mut writer);
        writer.finish()
    }

    /// Writes the nodes to a TL writer.
    pub fn write_to(&self, writer: &mut TlWriter) {
        writer.write_u32(OVERLAY_NODES);
        writer.write_u32(self.nodes.len() as u32);
        for node in &self.nodes {
            // Write node without schema ID prefix (it's already in the node)
            writer.write_u32(PUB_ED25519);
            writer.write_int256(&node.id);
            writer.write_int256(&node.overlay);
            writer.write_i32(node.version);
            writer.write_bytes(&node.signature);
        }
    }

    /// Parses nodes from TL format.
    pub fn from_tl(data: &[u8]) -> Result<Self> {
        let mut reader = TlReader::new(data);
        Self::read_from(&mut reader)
    }

    /// Reads nodes from a TL reader.
    pub fn read_from(reader: &mut TlReader) -> Result<Self> {
        let schema = reader.read_u32()?;
        if schema != OVERLAY_NODES {
            return Err(OverlayError::TlError(format!(
                "expected overlay.nodes (0x{:08x}), got 0x{:08x}",
                OVERLAY_NODES, schema
            )));
        }

        let count = reader.read_u32()? as usize;
        let mut nodes = Vec::with_capacity(count);

        for _ in 0..count {
            // Read public key
            let key_type = reader.read_u32()?;
            if key_type != PUB_ED25519 {
                return Err(OverlayError::TlError(format!(
                    "expected pub.ed25519 (0x{:08x}), got 0x{:08x}",
                    PUB_ED25519, key_type
                )));
            }

            let id = reader.read_int256()?;
            let overlay = reader.read_int256()?;
            let version = reader.read_i32()?;
            let signature = reader.read_bytes()?;

            nodes.push(OverlayNode {
                id,
                overlay,
                version,
                signature,
            });
        }

        Ok(Self { nodes })
    }
}

impl IntoIterator for OverlayNodes {
    type Item = OverlayNode;
    type IntoIter = std::vec::IntoIter<OverlayNode>;

    fn into_iter(self) -> Self::IntoIter {
        self.nodes.into_iter()
    }
}

impl<'a> IntoIterator for &'a OverlayNodes {
    type Item = &'a OverlayNode;
    type IntoIter = std::slice::Iter<'a, OverlayNode>;

    fn into_iter(self) -> Self::IntoIter {
        self.nodes.iter()
    }
}

/// Peer information for an overlay node.
#[derive(Debug, Clone)]
pub struct OverlayPeer {
    /// The overlay node.
    pub node: OverlayNode,
    /// Last seen timestamp.
    pub last_seen: i32,
    /// Number of successful queries.
    pub success_count: u32,
    /// Number of failed queries.
    pub failure_count: u32,
}

impl OverlayPeer {
    /// Creates a new peer from an overlay node.
    pub fn new(node: OverlayNode) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i32;

        Self {
            node,
            last_seen: now,
            success_count: 0,
            failure_count: 0,
        }
    }

    /// Updates the last seen timestamp.
    pub fn touch(&mut self) {
        self.last_seen = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i32;
    }

    /// Records a successful query.
    pub fn record_success(&mut self) {
        self.touch();
        self.success_count = self.success_count.saturating_add(1);
    }

    /// Records a failed query.
    pub fn record_failure(&mut self) {
        self.failure_count = self.failure_count.saturating_add(1);
    }

    /// Updates the peer with a newer node version.
    ///
    /// This implements the official TON OverlayNodes merge strategy:
    /// - Updates the node data while preserving peer statistics
    /// - Updates the last_seen timestamp
    ///
    /// Reference: ton-blockchain/ton/overlay/overlay-peers.cpp
    pub fn update(&mut self, node: OverlayNode) {
        self.node = node;
        self.touch();
    }

    /// Returns the peer's reliability score.
    pub fn reliability_score(&self) -> f64 {
        let total = self.success_count + self.failure_count;
        if total == 0 {
            return 0.5; // Unknown reliability
        }
        self.success_count as f64 / total as f64
    }

    /// Returns the node ID.
    pub fn node_id(&self) -> [u8; 32] {
        self.node.node_id()
    }

    /// Returns the public key.
    pub fn public_key(&self) -> &[u8; 32] {
        &self.node.id
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_overlay_node_creation() {
        let keypair = Ed25519Keypair::generate();
        let overlay = [1u8; 32];

        let node = OverlayNode::from_keypair(&keypair, overlay);

        assert_eq!(node.id, keypair.public_key);
        assert_eq!(node.overlay, overlay);
        assert!(!node.signature.is_empty());
    }

    #[test]
    fn test_overlay_node_signature() {
        let keypair = Ed25519Keypair::generate();
        let overlay = [1u8; 32];

        let node = OverlayNode::from_keypair(&keypair, overlay);
        assert!(node.verify_signature().is_ok());
    }

    #[test]
    fn test_overlay_node_roundtrip() {
        let keypair = Ed25519Keypair::generate();
        let overlay = [1u8; 32];

        let node = OverlayNode::from_keypair(&keypair, overlay);
        let tl_data = node.to_tl();
        let parsed = OverlayNode::from_tl(&tl_data).unwrap();

        assert_eq!(parsed.id, node.id);
        assert_eq!(parsed.overlay, node.overlay);
        assert_eq!(parsed.version, node.version);
        assert_eq!(parsed.signature, node.signature);

        assert!(parsed.verify_signature().is_ok());
    }

    #[test]
    fn test_overlay_node_invalid_signature() {
        let keypair = Ed25519Keypair::generate();
        let overlay = [1u8; 32];

        let mut node = OverlayNode::from_keypair(&keypair, overlay);

        // Corrupt the signature
        if !node.signature.is_empty() {
            node.signature[0] ^= 0xFF;
        }

        assert!(node.verify_signature().is_err());
    }

    #[test]
    fn test_overlay_node_id() {
        let keypair = Ed25519Keypair::generate();
        let overlay = [1u8; 32];

        let node = OverlayNode::from_keypair(&keypair, overlay);
        let node_id = node.node_id();

        // Node ID should be 32 bytes
        assert_eq!(node_id.len(), 32);

        // Should be deterministic
        let node_id2 = node.node_id();
        assert_eq!(node_id, node_id2);
    }

    #[test]
    fn test_overlay_nodes_collection() {
        let keypair1 = Ed25519Keypair::generate();
        let keypair2 = Ed25519Keypair::generate();
        let overlay = [1u8; 32];

        let node1 = OverlayNode::from_keypair(&keypair1, overlay);
        let node2 = OverlayNode::from_keypair(&keypair2, overlay);

        let mut nodes = OverlayNodes::new();
        nodes.add(node1.clone());
        nodes.add(node2.clone());

        assert_eq!(nodes.len(), 2);

        // Adding duplicate should not increase count
        nodes.add(node1.clone());
        assert_eq!(nodes.len(), 2);
    }

    #[test]
    fn test_overlay_nodes_roundtrip() {
        let keypair1 = Ed25519Keypair::generate();
        let keypair2 = Ed25519Keypair::generate();
        let overlay = [1u8; 32];

        let node1 = OverlayNode::from_keypair(&keypair1, overlay);
        let node2 = OverlayNode::from_keypair(&keypair2, overlay);

        let nodes = OverlayNodes::with_nodes(vec![node1.clone(), node2.clone()]);
        let tl_data = nodes.to_tl();
        let parsed = OverlayNodes::from_tl(&tl_data).unwrap();

        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed.nodes[0].id, node1.id);
        assert_eq!(parsed.nodes[1].id, node2.id);
    }

    #[test]
    fn test_overlay_peer() {
        let keypair = Ed25519Keypair::generate();
        let overlay = [1u8; 32];
        let node = OverlayNode::from_keypair(&keypair, overlay);

        let mut peer = OverlayPeer::new(node);
        assert_eq!(peer.success_count, 0);
        assert_eq!(peer.failure_count, 0);
        assert_eq!(peer.reliability_score(), 0.5);

        // Record successes
        peer.record_success();
        peer.record_success();
        peer.record_success();
        assert_eq!(peer.success_count, 3);

        // Record failures
        peer.record_failure();
        assert_eq!(peer.failure_count, 1);

        // Reliability should be 3/4 = 0.75
        assert!((peer.reliability_score() - 0.75).abs() < 0.001);
    }

    #[test]
    fn test_overlay_node_is_recent() {
        let keypair = Ed25519Keypair::generate();
        let overlay = [1u8; 32];

        // Node with current version
        let node = OverlayNode::from_keypair(&keypair, overlay);
        assert!(node.is_recent(60)); // Within last 60 seconds

        // Node with old version
        let mut old_node = OverlayNode::new(keypair.public_key, overlay, 0);
        old_node.sign(&keypair);
        assert!(!old_node.is_recent(60));
    }
}
