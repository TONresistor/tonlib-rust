//! OverlayManager for joining and leaving overlay networks.
//!
//! The OverlayManager is the main entry point for participating in overlay networks.
//! It handles:
//! - Joining and leaving overlays
//! - Peer discovery via DHT and getRandomPeers queries
//! - Broadcast propagation
//! - Node presence announcements

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::RwLock;
use tracing::{debug, trace, warn};

use ton_adnl::udp::AdnlNode;
use ton_crypto::{sha256, Ed25519Keypair};
use ton_dht::DhtClient;

use crate::broadcast::{Broadcast, BroadcastCache, OverlayBroadcast, MAX_BROADCAST_SIZE};
use crate::certificate::OverlayCertificate;
use crate::error::{OverlayError, Result};
use crate::node::{OverlayNode, OverlayNodes, OverlayPeer};
use crate::overlay_id::{dht_key_for_overlay, OverlayId};
use crate::tl::{TlReader, TlWriter, OVERLAY_GET_RANDOM_PEERS, OVERLAY_NODES, OVERLAY_QUERY, PUB_ED25519};

/// Default maximum number of peers per overlay.
pub const DEFAULT_MAX_PEERS: usize = 20;

/// Default peer discovery interval in seconds.
pub const DEFAULT_DISCOVERY_INTERVAL: u64 = 60;

/// Default broadcast cache size.
pub const DEFAULT_BROADCAST_CACHE_SIZE: usize = 10000;

/// Default query timeout.
pub const DEFAULT_QUERY_TIMEOUT: Duration = Duration::from_secs(10);

/// Maximum age for an overlay node version (in seconds).
/// Nodes with versions older than this are considered stale and rejected.
/// Reference: ton-blockchain/ton/overlay/overlay-peers.cpp
pub const MAX_NODE_VERSION_AGE: i32 = 3600; // 1 hour

/// Maximum time in the future for an overlay node version (in seconds).
/// Nodes with versions too far in the future are rejected.
/// Reference: ton-blockchain/ton/overlay/overlay-peers.cpp
pub const MAX_NODE_VERSION_FUTURE: i32 = 120; // 2 minutes

/// Configuration for an overlay.
#[derive(Debug, Clone)]
pub struct OverlayConfig {
    /// Maximum number of peers to maintain.
    pub max_peers: usize,
    /// How often to discover new peers (seconds).
    pub discovery_interval: u64,
    /// Broadcast cache size.
    pub broadcast_cache_size: usize,
    /// Query timeout.
    pub query_timeout: Duration,
}

impl Default for OverlayConfig {
    fn default() -> Self {
        Self {
            max_peers: DEFAULT_MAX_PEERS,
            discovery_interval: DEFAULT_DISCOVERY_INTERVAL,
            broadcast_cache_size: DEFAULT_BROADCAST_CACHE_SIZE,
            query_timeout: DEFAULT_QUERY_TIMEOUT,
        }
    }
}

/// State for a single overlay network.
#[derive(Debug)]
pub struct OverlayState {
    /// The overlay ID.
    pub overlay_id: OverlayId,
    /// Our node in this overlay.
    pub local_node: OverlayNode,
    /// Known peers in this overlay.
    pub peers: HashMap<[u8; 32], OverlayPeer>,
    /// Broadcast cache for duplicate detection.
    pub broadcast_cache: BroadcastCache,
    /// Configuration for this overlay.
    pub config: OverlayConfig,
}

impl OverlayState {
    /// Creates a new overlay state.
    pub fn new(overlay_id: OverlayId, local_node: OverlayNode, config: OverlayConfig) -> Self {
        Self {
            overlay_id,
            local_node,
            peers: HashMap::new(),
            broadcast_cache: BroadcastCache::new(config.broadcast_cache_size),
            config,
        }
    }

    /// Adds or updates a peer in the overlay.
    ///
    /// This implements the official TON OverlayNodes update rule:
    /// - Validates node version is within acceptable time window
    /// - If the node already exists, update it with the newer version
    /// - If the node is new, add it (up to max_peers limit)
    ///
    /// Returns true if the node was added or updated, false if rejected.
    ///
    /// Reference: ton-blockchain/ton/overlay/overlay-peers.cpp
    pub fn add_peer(&mut self, node: OverlayNode) -> bool {
        // Validate node version TTL (official TON behavior)
        // Reject nodes with versions too old or too far in the future
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i32;

        // Check if version is too old
        if node.version < now - MAX_NODE_VERSION_AGE {
            trace!("Rejecting node with stale version: {} < {} - {}",
                   node.version, now, MAX_NODE_VERSION_AGE);
            return false;
        }

        // Check if version is too far in the future
        if node.version > now + MAX_NODE_VERSION_FUTURE {
            trace!("Rejecting node with future version: {} > {} + {}",
                   node.version, now, MAX_NODE_VERSION_FUTURE);
            return false;
        }

        let node_id = node.node_id();

        // Check if peer already exists
        if let Some(existing_peer) = self.peers.get_mut(&node_id) {
            // Update existing peer if new version is newer (merge strategy)
            if node.version > existing_peer.node.version {
                existing_peer.update(node);
                return true;
            }
            // Same or older version, no update needed
            return false;
        }

        // New peer - check max_peers limit
        if self.peers.len() >= self.config.max_peers {
            return false;
        }

        self.peers.insert(node_id, OverlayPeer::new(node));
        true
    }

    /// Removes a peer from the overlay.
    pub fn remove_peer(&mut self, node_id: &[u8; 32]) {
        self.peers.remove(node_id);
    }

    /// Returns the number of peers.
    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }

    /// Returns an iterator over the peers.
    pub fn peers(&self) -> impl Iterator<Item = &OverlayPeer> {
        self.peers.values()
    }

    /// Gets a peer by node ID.
    pub fn get_peer(&self, node_id: &[u8; 32]) -> Option<&OverlayPeer> {
        self.peers.get(node_id)
    }

    /// Gets a mutable peer by node ID.
    pub fn get_peer_mut(&mut self, node_id: &[u8; 32]) -> Option<&mut OverlayPeer> {
        self.peers.get_mut(node_id)
    }

    /// Selects random peers for broadcast forwarding.
    pub fn select_random_peers(&self, count: usize) -> Vec<&OverlayPeer> {
        use rand::seq::SliceRandom;
        let mut peers: Vec<_> = self.peers.values().collect();
        peers.shuffle(&mut rand::thread_rng());
        peers.truncate(count);
        peers
    }
}

/// Manager for overlay networks.
pub struct OverlayManager {
    /// Our keypair for signing.
    keypair: Ed25519Keypair,
    /// The ADNL node for network communication.
    adnl: Arc<RwLock<AdnlNode>>,
    /// The DHT client for peer discovery.
    dht: Option<Arc<RwLock<DhtClient>>>,
    /// Active overlays.
    overlays: HashMap<[u8; 32], OverlayState>,
    /// Default configuration for new overlays.
    default_config: OverlayConfig,
}

impl OverlayManager {
    /// Creates a new overlay manager.
    pub fn new(keypair: Ed25519Keypair, adnl: Arc<RwLock<AdnlNode>>) -> Self {
        Self {
            keypair,
            adnl,
            dht: None,
            overlays: HashMap::new(),
            default_config: OverlayConfig::default(),
        }
    }

    /// Sets the DHT client for peer discovery.
    pub fn with_dht(mut self, dht: Arc<RwLock<DhtClient>>) -> Self {
        self.dht = Some(dht);
        self
    }

    /// Sets the default configuration for new overlays.
    pub fn with_config(mut self, config: OverlayConfig) -> Self {
        self.default_config = config;
        self
    }

    /// Returns our public key.
    pub fn public_key(&self) -> &[u8; 32] {
        &self.keypair.public_key
    }

    /// Computes our node ID.
    pub fn local_node_id(&self) -> [u8; 32] {
        let mut writer = TlWriter::new();
        writer.write_u32(PUB_ED25519);
        writer.write_int256(&self.keypair.public_key);
        sha256(&writer.finish())
    }

    /// Joins an overlay network.
    pub async fn join_overlay(&mut self, overlay_id: OverlayId) -> Result<()> {
        self.join_overlay_with_config(overlay_id, self.default_config.clone())
            .await
    }

    /// Joins an overlay network with custom configuration.
    pub async fn join_overlay_with_config(
        &mut self,
        overlay_id: OverlayId,
        config: OverlayConfig,
    ) -> Result<()> {
        let overlay_bytes = overlay_id.to_bytes();

        if self.overlays.contains_key(&overlay_bytes) {
            debug!("Already joined overlay {}", overlay_id);
            return Ok(());
        }

        debug!("Joining overlay {}", overlay_id);

        // Create our local node for this overlay
        let local_node = OverlayNode::from_keypair(&self.keypair, overlay_bytes);

        // Create overlay state
        let state = OverlayState::new(overlay_id, local_node, config);
        self.overlays.insert(overlay_bytes, state);

        // Discover peers
        self.discover_peers(&overlay_bytes).await?;

        // Announce our presence
        self.announce_presence(&overlay_bytes).await?;

        Ok(())
    }

    /// Leaves an overlay network.
    pub fn leave_overlay(&mut self, overlay_id: &OverlayId) {
        let overlay_bytes = overlay_id.to_bytes();
        if self.overlays.remove(&overlay_bytes).is_some() {
            debug!("Left overlay {}", overlay_id);
        }
    }

    /// Returns true if we're in the given overlay.
    pub fn is_in_overlay(&self, overlay_id: &OverlayId) -> bool {
        self.overlays.contains_key(overlay_id.as_bytes())
    }

    /// Returns the state of an overlay.
    pub fn get_overlay(&self, overlay_id: &[u8; 32]) -> Option<&OverlayState> {
        self.overlays.get(overlay_id)
    }

    /// Returns the mutable state of an overlay.
    pub fn get_overlay_mut(&mut self, overlay_id: &[u8; 32]) -> Option<&mut OverlayState> {
        self.overlays.get_mut(overlay_id)
    }

    /// Returns all overlay IDs we're currently in.
    pub fn overlay_ids(&self) -> Vec<[u8; 32]> {
        self.overlays.keys().copied().collect()
    }

    /// Discovers peers for an overlay via DHT and getRandomPeers.
    async fn discover_peers(&mut self, overlay_id: &[u8; 32]) -> Result<()> {
        // Try DHT discovery first
        if let Some(dht) = &self.dht {
            let dht_key = dht_key_for_overlay(overlay_id);
            let dht_client = dht.read().await;

            match dht_client.find_value(&dht_key, 10).await {
                Ok(result) => {
                    if let ton_dht::DhtValueResult::Found(value) = result {
                        // Parse overlay nodes from DHT value
                        if let Ok(nodes) = OverlayNodes::from_tl(&value.value) {
                            drop(dht_client);
                            for node in nodes {
                                self.add_peer_to_overlay(overlay_id, node).await?;
                            }
                        }
                    }
                }
                Err(e) => {
                    debug!("DHT lookup failed for overlay: {}", e);
                }
            }
        }

        // Get more peers via getRandomPeers queries
        self.query_random_peers(overlay_id).await?;

        Ok(())
    }

    /// Queries existing peers for more peers.
    async fn query_random_peers(&mut self, overlay_id: &[u8; 32]) -> Result<()> {
        let state = self.overlays.get(overlay_id).ok_or_else(|| {
            OverlayError::OverlayNotFound(hex::encode(overlay_id))
        })?;

        // Get a list of peers to query
        let peers_to_query: Vec<_> = state
            .peers()
            .take(3)
            .map(|p| (p.node.id, p.node.node_id()))
            .collect();

        for (public_key, _node_id) in peers_to_query {
            match self.send_get_random_peers(overlay_id, &public_key).await {
                Ok(nodes) => {
                    for node in nodes {
                        // Verify the node belongs to this overlay
                        if node.overlay == *overlay_id
                            && let Err(e) = self.add_peer_to_overlay(overlay_id, node).await {
                                debug!("Failed to add peer: {}", e);
                            }
                    }
                }
                Err(e) => {
                    debug!("Failed to get random peers: {}", e);
                }
            }
        }

        Ok(())
    }

    /// Sends a getRandomPeers query to a peer.
    async fn send_get_random_peers(
        &self,
        overlay_id: &[u8; 32],
        peer_pubkey: &[u8; 32],
    ) -> Result<Vec<OverlayNode>> {
        let state = self.overlays.get(overlay_id).ok_or_else(|| {
            OverlayError::OverlayNotFound(hex::encode(overlay_id))
        })?;

        // Build getRandomPeers query
        let mut query = TlWriter::new();

        // Add overlay.query prefix
        query.write_u32(OVERLAY_QUERY);
        query.write_int256(overlay_id);

        // Add getRandomPeers request
        query.write_u32(OVERLAY_GET_RANDOM_PEERS);

        // Include our known peers
        let our_nodes: Vec<_> = state.peers().map(|p| &p.node).collect();
        query.write_u32(OVERLAY_NODES);
        query.write_u32(our_nodes.len() as u32);
        for node in our_nodes {
            query.write_u32(PUB_ED25519);
            query.write_int256(&node.id);
            query.write_int256(&node.overlay);
            query.write_i32(node.version);
            query.write_bytes(&node.signature);
        }

        // Send query via ADNL
        let mut adnl = self.adnl.write().await;
        let peer_id = adnl.get_peer_id(peer_pubkey);
        let response = adnl.send_query(&peer_id, &query.finish()).await?;
        drop(adnl);

        // Parse response
        let mut reader = TlReader::new(&response);
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

        Ok(nodes)
    }

    /// Adds a peer to an overlay.
    async fn add_peer_to_overlay(
        &mut self,
        overlay_id: &[u8; 32],
        node: OverlayNode,
    ) -> Result<()> {
        // Verify node signature
        node.verify_signature()?;

        // Check node belongs to this overlay
        if node.overlay != *overlay_id {
            return Err(OverlayError::InvalidNode(
                "node overlay ID mismatch".into(),
            ));
        }

        // Add to state
        let state = self.overlays.get_mut(overlay_id).ok_or_else(|| {
            OverlayError::OverlayNotFound(hex::encode(overlay_id))
        })?;

        if !state.add_peer(node.clone()) {
            trace!("Peer already known or max peers reached");
        }

        // Add to ADNL (note: we'd need address info in a real implementation)
        // For now, we assume ADNL already knows about this peer

        Ok(())
    }

    /// Announces our presence in the overlay.
    async fn announce_presence(&self, overlay_id: &[u8; 32]) -> Result<()> {
        let state = self.overlays.get(overlay_id).ok_or_else(|| {
            OverlayError::OverlayNotFound(hex::encode(overlay_id))
        })?;

        // Create a broadcast with our node info
        let node_data = state.local_node.to_tl();

        if node_data.len() <= MAX_BROADCAST_SIZE {
            // Use simple broadcast for node announcement
            let mut broadcast = OverlayBroadcast::new(node_data);
            broadcast.sign(&self.keypair, overlay_id);

            // Send to all peers
            for peer in state.peers() {
                if let Err(e) = self.send_broadcast_to_peer(overlay_id, &peer.node.id, &broadcast).await {
                    debug!("Failed to send presence announcement: {}", e);
                }
            }
        }

        Ok(())
    }

    /// Sends a broadcast to a specific peer.
    async fn send_broadcast_to_peer(
        &self,
        overlay_id: &[u8; 32],
        peer_pubkey: &[u8; 32],
        broadcast: &OverlayBroadcast,
    ) -> Result<()> {
        // Build message with overlay prefix
        let mut message = TlWriter::new();
        message.write_u32(OVERLAY_QUERY);
        message.write_int256(overlay_id);
        message.write_raw(&broadcast.to_tl());

        // Send via ADNL
        let mut adnl = self.adnl.write().await;
        let peer_id = adnl.get_peer_id(peer_pubkey);
        adnl.send_custom(&peer_id, &message.finish()).await?;

        Ok(())
    }

    /// Broadcasts data to all peers in an overlay.
    pub async fn broadcast(
        &mut self,
        overlay_id: &[u8; 32],
        data: Vec<u8>,
    ) -> Result<()> {
        self.broadcast_with_certificate(overlay_id, data, OverlayCertificate::empty())
            .await
    }

    /// Broadcasts data with a certificate.
    pub async fn broadcast_with_certificate(
        &mut self,
        overlay_id: &[u8; 32],
        data: Vec<u8>,
        certificate: OverlayCertificate,
    ) -> Result<()> {
        if data.len() > MAX_BROADCAST_SIZE {
            return Err(OverlayError::BroadcastTooLarge {
                size: data.len(),
                max: MAX_BROADCAST_SIZE,
            });
        }

        let mut broadcast = OverlayBroadcast::new(data)
            .with_certificate(certificate);
        broadcast.sign(&self.keypair, overlay_id);

        // Mark as seen
        let data_hash = broadcast.data_hash();
        {
            let state = self.overlays.get_mut(overlay_id).ok_or_else(|| {
                OverlayError::OverlayNotFound(hex::encode(overlay_id))
            })?;
            state.broadcast_cache.mark_seen(data_hash);
        }

        // Send to all peers
        let state = self.overlays.get(overlay_id).ok_or_else(|| {
            OverlayError::OverlayNotFound(hex::encode(overlay_id))
        })?;

        for peer in state.peers() {
            if let Err(e) = self.send_broadcast_to_peer(overlay_id, &peer.node.id, &broadcast).await {
                warn!("Failed to send broadcast to peer: {}", e);
            }
        }

        Ok(())
    }

    /// Handles a received broadcast.
    pub async fn handle_broadcast(
        &mut self,
        overlay_id: &[u8; 32],
        broadcast: Broadcast,
    ) -> Result<Option<Vec<u8>>> {
        let data_hash = broadcast.data_hash();

        // Check if already seen
        let state = self.overlays.get_mut(overlay_id).ok_or_else(|| {
            OverlayError::OverlayNotFound(hex::encode(overlay_id))
        })?;

        if !state.broadcast_cache.mark_seen(data_hash) {
            // Already seen
            return Err(OverlayError::BroadcastDuplicate);
        }

        // Validate and process based on type
        match broadcast {
            Broadcast::Simple(b) => {
                // Validate
                b.validate(overlay_id)?;

                // Forward to other peers
                let peers_to_forward: Vec<_> = state
                    .select_random_peers(5)
                    .iter()
                    .filter(|p| p.node.id != b.src)
                    .map(|p| p.node.id)
                    .collect();

                // state goes out of scope after we extract the data

                for peer_pubkey in peers_to_forward {
                    if let Err(e) = self.send_broadcast_to_peer(overlay_id, &peer_pubkey, &b).await {
                        debug!("Failed to forward broadcast: {}", e);
                    }
                }

                Ok(Some(b.data))
            }
            Broadcast::Fec(b) => {
                // FEC broadcasts require special handling with RLDP
                // For now, just verify signature
                b.verify_signature(overlay_id)?;
                Ok(Some(b.data))
            }
            Broadcast::FecShort(_) => {
                // Short FEC broadcasts are part of an ongoing FEC transfer
                Ok(None)
            }
        }
    }

    /// Performs periodic maintenance tasks.
    pub async fn maintenance(&mut self) {
        for state in self.overlays.values_mut() {
            // Remove stale peers (not seen in 5 minutes)
            let stale_threshold = 300;
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i32;

            let stale_peers: Vec<_> = state
                .peers
                .iter()
                .filter(|(_, peer)| peer.last_seen < now - stale_threshold)
                .map(|(id, _)| *id)
                .collect();

            for peer_id in stale_peers {
                state.remove_peer(&peer_id);
                debug!("Removed stale peer {:?}", hex::encode(&peer_id[..8]));
            }
        }
    }

    /// Returns statistics about an overlay.
    pub fn overlay_stats(&self, overlay_id: &[u8; 32]) -> Option<OverlayStats> {
        let state = self.overlays.get(overlay_id)?;
        Some(OverlayStats {
            peer_count: state.peer_count(),
            broadcast_cache_size: state.broadcast_cache.len(),
        })
    }
}

/// Statistics for an overlay.
#[derive(Debug, Clone)]
pub struct OverlayStats {
    /// Number of peers.
    pub peer_count: usize,
    /// Number of cached broadcast hashes.
    pub broadcast_cache_size: usize,
}

/// Hex encoding helper (for debugging).
mod hex {
    pub fn encode(data: &[u8]) -> String {
        data.iter().map(|b| format!("{:02x}", b)).collect()
    }

    pub fn encode_array(data: &[u8; 32]) -> String {
        data.iter().map(|b| format!("{:02x}", b)).collect()
    }
}

impl std::fmt::Debug for OverlayManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OverlayManager")
            .field("overlays", &self.overlays.keys().map(hex::encode_array).collect::<Vec<_>>())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_overlay_state_creation() {
        let keypair = Ed25519Keypair::generate();
        let overlay_id = OverlayId::from_bytes([1u8; 32]);
        let local_node = OverlayNode::from_keypair(&keypair, overlay_id.to_bytes());
        let config = OverlayConfig::default();

        let state = OverlayState::new(overlay_id, local_node, config);
        assert_eq!(state.peer_count(), 0);
    }

    #[test]
    fn test_overlay_state_add_peer() {
        let keypair1 = Ed25519Keypair::generate();
        let keypair2 = Ed25519Keypair::generate();
        let overlay_id = OverlayId::from_bytes([1u8; 32]);
        let local_node = OverlayNode::from_keypair(&keypair1, overlay_id.to_bytes());
        let config = OverlayConfig::default();

        let mut state = OverlayState::new(overlay_id, local_node, config);

        let peer_node = OverlayNode::from_keypair(&keypair2, overlay_id.to_bytes());
        assert!(state.add_peer(peer_node.clone()));
        assert_eq!(state.peer_count(), 1);

        // Adding same version should return false (no update needed)
        assert!(!state.add_peer(peer_node));
        assert_eq!(state.peer_count(), 1);
    }

    #[test]
    fn test_overlay_state_update_peer() {
        let keypair1 = Ed25519Keypair::generate();
        let keypair2 = Ed25519Keypair::generate();
        let overlay_id = OverlayId::from_bytes([1u8; 32]);
        let local_node = OverlayNode::from_keypair(&keypair1, overlay_id.to_bytes());
        let config = OverlayConfig::default();

        let mut state = OverlayState::new(overlay_id, local_node, config);

        // Use valid timestamps (relative to current time)
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i32;

        // Add peer with current time version
        let version_1 = now - 10;  // 10 seconds ago
        let mut peer_node = OverlayNode::new(keypair2.public_key, overlay_id.to_bytes(), version_1);
        peer_node.sign(&keypair2);
        assert!(state.add_peer(peer_node.clone()));
        assert_eq!(state.peer_count(), 1);

        // Verify original version
        let node_id = peer_node.node_id();
        assert_eq!(state.get_peer(&node_id).unwrap().node.version, version_1);

        // Update with newer version - should succeed
        let version_2 = now - 5;  // 5 seconds ago (newer)
        let mut newer_node = OverlayNode::new(keypair2.public_key, overlay_id.to_bytes(), version_2);
        newer_node.sign(&keypair2);
        assert!(state.add_peer(newer_node));
        assert_eq!(state.peer_count(), 1); // Still 1 peer (updated, not added)
        assert_eq!(state.get_peer(&node_id).unwrap().node.version, version_2);

        // Update with older version - should fail (no downgrade)
        let version_3 = now - 8;  // 8 seconds ago (older than version_2)
        let mut older_node = OverlayNode::new(keypair2.public_key, overlay_id.to_bytes(), version_3);
        older_node.sign(&keypair2);
        assert!(!state.add_peer(older_node));
        assert_eq!(state.get_peer(&node_id).unwrap().node.version, version_2); // Still version_2
    }

    #[test]
    fn test_overlay_state_max_peers() {
        let keypair = Ed25519Keypair::generate();
        let overlay_id = OverlayId::from_bytes([1u8; 32]);
        let local_node = OverlayNode::from_keypair(&keypair, overlay_id.to_bytes());
        let config = OverlayConfig {
            max_peers: 2,
            ..Default::default()
        };

        let mut state = OverlayState::new(overlay_id, local_node, config);

        // Add peers up to limit
        for i in 0..3 {
            let peer_keypair = Ed25519Keypair::generate();
            let peer_node = OverlayNode::from_keypair(&peer_keypair, overlay_id.to_bytes());
            let added = state.add_peer(peer_node);

            if i < 2 {
                assert!(added);
            } else {
                assert!(!added); // Should fail due to max_peers
            }
        }

        assert_eq!(state.peer_count(), 2);
    }

    #[test]
    fn test_overlay_config_default() {
        let config = OverlayConfig::default();
        assert_eq!(config.max_peers, DEFAULT_MAX_PEERS);
        assert_eq!(config.discovery_interval, DEFAULT_DISCOVERY_INTERVAL);
        assert_eq!(config.broadcast_cache_size, DEFAULT_BROADCAST_CACHE_SIZE);
    }

    #[test]
    fn test_overlay_stats() {
        let keypair = Ed25519Keypair::generate();
        let overlay_id = OverlayId::from_bytes([1u8; 32]);
        let local_node = OverlayNode::from_keypair(&keypair, overlay_id.to_bytes());
        let config = OverlayConfig::default();

        let mut state = OverlayState::new(overlay_id, local_node, config);

        // Add some peers
        for _ in 0..3 {
            let peer_keypair = Ed25519Keypair::generate();
            let peer_node = OverlayNode::from_keypair(&peer_keypair, overlay_id.to_bytes());
            state.add_peer(peer_node);
        }

        // Mark some broadcasts as seen
        state.broadcast_cache.mark_seen([1u8; 32]);
        state.broadcast_cache.mark_seen([2u8; 32]);

        assert_eq!(state.peer_count(), 3);
        assert_eq!(state.broadcast_cache.len(), 2);
    }

    #[test]
    fn test_overlay_state_reject_stale_node() {
        // Test that nodes with versions too old are rejected (TTL validation)
        let keypair1 = Ed25519Keypair::generate();
        let keypair2 = Ed25519Keypair::generate();
        let overlay_id = OverlayId::from_bytes([1u8; 32]);
        let local_node = OverlayNode::from_keypair(&keypair1, overlay_id.to_bytes());
        let config = OverlayConfig::default();

        let mut state = OverlayState::new(overlay_id, local_node, config);

        // Create a node with a very old version (2 hours ago)
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i32;

        let old_version = now - MAX_NODE_VERSION_AGE - 3600; // 1h past the max age
        let mut stale_node = OverlayNode::new(keypair2.public_key, overlay_id.to_bytes(), old_version);
        stale_node.sign(&keypair2);

        // Should be rejected due to TTL
        assert!(!state.add_peer(stale_node), "Stale node should be rejected");
        assert_eq!(state.peer_count(), 0);
    }

    #[test]
    fn test_overlay_state_reject_future_node() {
        // Test that nodes with versions too far in the future are rejected
        let keypair1 = Ed25519Keypair::generate();
        let keypair2 = Ed25519Keypair::generate();
        let overlay_id = OverlayId::from_bytes([1u8; 32]);
        let local_node = OverlayNode::from_keypair(&keypair1, overlay_id.to_bytes());
        let config = OverlayConfig::default();

        let mut state = OverlayState::new(overlay_id, local_node, config);

        // Create a node with a future version (10 minutes in the future)
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i32;

        let future_version = now + MAX_NODE_VERSION_FUTURE + 600; // 10min past the max future
        let mut future_node = OverlayNode::new(keypair2.public_key, overlay_id.to_bytes(), future_version);
        future_node.sign(&keypair2);

        // Should be rejected due to future TTL
        assert!(!state.add_peer(future_node), "Future node should be rejected");
        assert_eq!(state.peer_count(), 0);
    }

    #[test]
    fn test_overlay_state_accept_valid_ttl_node() {
        // Test that nodes with valid TTL are accepted
        let keypair1 = Ed25519Keypair::generate();
        let keypair2 = Ed25519Keypair::generate();
        let overlay_id = OverlayId::from_bytes([1u8; 32]);
        let local_node = OverlayNode::from_keypair(&keypair1, overlay_id.to_bytes());
        let config = OverlayConfig::default();

        let mut state = OverlayState::new(overlay_id, local_node, config);

        // Node with current time should be accepted
        let peer_node = OverlayNode::from_keypair(&keypair2, overlay_id.to_bytes());
        assert!(state.add_peer(peer_node), "Valid node should be accepted");
        assert_eq!(state.peer_count(), 1);
    }

    #[test]
    fn test_node_ttl_constants_match_official_ton() {
        // Verify TTL constants match official TON implementation
        // Reference: ton-blockchain/ton/overlay/overlay-peers.cpp
        assert_eq!(MAX_NODE_VERSION_AGE, 3600, "Max node age should be 1 hour");
        assert_eq!(MAX_NODE_VERSION_FUTURE, 120, "Max future should be 2 minutes");
    }
}
