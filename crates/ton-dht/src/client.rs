//! DHT client implementation.
//!
//! The DHT client provides the main interface for interacting with the TON DHT network.
//! It handles:
//! - Finding values by key
//! - Finding nodes by key
//! - Storing values
//! - Managing the routing table

use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::RwLock;
use tracing::{debug, trace, warn};

use ton_adnl::udp::AdnlNode;
use ton_crypto::sha256::sha256;

use crate::bootstrap::BootstrapManager;
use crate::distance::compare_distance;
use crate::error::{DhtError, Result};
use crate::node::{DhtNode, DhtNodes};
use crate::routing::RoutingTable;
use crate::tl::{
    TlReader, TlWriter, DHT_FIND_NODE, DHT_FIND_VALUE, DHT_NODES, DHT_PING, DHT_PONG, DHT_STORE,
    DHT_STORED, DHT_VALUE_FOUND, DHT_VALUE_NOT_FOUND, PUB_ED25519,
};
use crate::validation::ValueValidator;
use crate::value::{DhtValue, DhtValueResult};

/// Default number of parallel lookups.
pub const DEFAULT_ALPHA: usize = 3;

/// Default number of results to return.
pub const DEFAULT_K: u8 = 10;

/// Default query timeout (matching official TON: ~3s base with jitter).
/// Reference: ton-blockchain/ton/dht/dht-query.cpp - td::Timestamp::in(2.0 + rand * 0.1)
pub const DEFAULT_TIMEOUT: Duration = Duration::from_millis(3000);

/// Maximum number of iterations in a lookup.
pub const MAX_ITERATIONS: usize = 20;

/// DHT client for interacting with the TON DHT network.
pub struct DhtClient {
    /// The ADNL node for network communication.
    adnl: Arc<RwLock<AdnlNode>>,
    /// The Kademlia routing table.
    routing_table: Arc<RwLock<RoutingTable>>,
    /// Our local node ID.
    local_id: [u8; 32],
    /// Query timeout.
    timeout: Duration,
    /// Number of parallel lookups (alpha parameter).
    alpha: usize,
    /// Bootstrap manager.
    bootstrap_manager: Arc<RwLock<BootstrapManager>>,
}

impl DhtClient {
    /// Creates a new DHT client with the given ADNL node.
    pub fn new(adnl: AdnlNode) -> Self {
        let local_id = Self::compute_local_id(adnl.public_key());
        let routing_table = RoutingTable::new(local_id);

        let client = Self {
            adnl: Arc::new(RwLock::new(adnl)),
            routing_table: Arc::new(RwLock::new(routing_table)),
            local_id,
            timeout: DEFAULT_TIMEOUT,
            alpha: DEFAULT_ALPHA,
            bootstrap_manager: Arc::new(RwLock::new(BootstrapManager::empty())),
        };

        // Start background eviction task
        client.start_background_eviction_task();

        client
    }

    /// Creates a new DHT client with custom configuration.
    pub fn with_config(adnl: AdnlNode, timeout: Duration, alpha: usize) -> Self {
        let local_id = Self::compute_local_id(adnl.public_key());
        let routing_table = RoutingTable::new(local_id);

        let client = Self {
            adnl: Arc::new(RwLock::new(adnl)),
            routing_table: Arc::new(RwLock::new(routing_table)),
            local_id,
            timeout,
            alpha,
            bootstrap_manager: Arc::new(RwLock::new(BootstrapManager::empty())),
        };

        // Start background eviction task
        client.start_background_eviction_task();

        client
    }

    /// Computes the local node ID from a public key.
    fn compute_local_id(public_key: &[u8; 32]) -> [u8; 32] {
        let mut writer = TlWriter::new();
        writer.write_u32(PUB_ED25519);
        writer.write_int256(public_key);
        sha256(&writer.finish())
    }

    /// Returns the local node ID.
    pub fn local_id(&self) -> &[u8; 32] {
        &self.local_id
    }

    /// Sets the query timeout.
    pub fn set_timeout(&mut self, timeout: Duration) {
        self.timeout = timeout;
    }

    /// Sets the alpha parameter (number of parallel lookups).
    pub fn set_alpha(&mut self, alpha: usize) {
        self.alpha = alpha;
    }

    /// Adds a node to the routing table.
    pub async fn add_node(&self, node: DhtNode) {
        // Verify the node's signature
        if let Err(e) = node.verify_signature() {
            warn!("Ignoring node with invalid signature: {}", e);
            return;
        }

        let mut table = self.routing_table.write().await;
        table.add(node);
    }

    /// Adds a bootstrap node.
    pub async fn add_bootstrap_node(&self, addr: SocketAddr, public_key: &[u8; 32]) -> Result<()> {
        let mut adnl = self.adnl.write().await;
        adnl.add_peer(addr, public_key).await?;

        // Create a DhtNode for the bootstrap node
        let addr_list = crate::node::AdnlAddressList::from_socket_addr(addr);
        let node = DhtNode::with_current_version(*public_key, addr_list);

        drop(adnl);
        self.add_node(node).await;

        Ok(())
    }

    /// Pings a node and returns the pong response.
    pub async fn ping(&self, node: &DhtNode) -> Result<i64> {
        let random_id = rand::random::<i64>();

        let mut query = TlWriter::new();
        query.write_u32(DHT_PING);
        query.write_i64(random_id);

        let response = self.query_node(node, &query.finish()).await?;

        let mut reader = TlReader::new(&response);
        let schema = reader.read_u32()?;
        if schema != DHT_PONG {
            return Err(DhtError::TlError(format!(
                "expected dht.pong (0x{:08x}), got 0x{:08x}",
                DHT_PONG, schema
            )));
        }

        let pong_id = reader.read_i64()?;
        if pong_id != random_id {
            return Err(DhtError::TlError("ping/pong ID mismatch".into()));
        }

        Ok(pong_id)
    }

    /// Finds a value in the DHT by its key.
    ///
    /// This implements the Kademlia iterative lookup algorithm with parallel queries:
    /// 1. Start with the k closest nodes from our routing table
    /// 2. Query alpha nodes in parallel (alpha=3 by default, matching official TON)
    /// 3. If value found, verify and return
    /// 4. Otherwise, add returned nodes to candidates and continue
    ///
    /// Reference: ton-blockchain/ton/dht/dht-query.cpp (DhtQuery with alpha parameter)
    pub async fn find_value(&self, key: &[u8; 32], k: u8) -> Result<DhtValueResult> {
        let mut visited = HashSet::new();

        // Get initial candidates from routing table
        let table = self.routing_table.read().await;
        let mut candidates: Vec<DhtNode> = table.closest_nodes(key, k as usize);
        drop(table);

        // Sort by distance to key
        candidates.sort_by(|a, b| compare_distance(key, &a.node_id(), &b.node_id()));

        let mut iterations = 0;

        while !candidates.is_empty() && iterations < MAX_ITERATIONS {
            iterations += 1;

            // Get the next alpha unvisited nodes for parallel queries
            // (Official TON uses alpha=3 for concurrent queries)
            let nodes_to_query: Vec<DhtNode> = candidates
                .iter()
                .filter(|n| !visited.contains(&n.node_id()))
                .take(self.alpha)
                .cloned()
                .collect();

            if nodes_to_query.is_empty() {
                break;
            }

            // Mark as visited
            for node in &nodes_to_query {
                visited.insert(node.node_id());
            }

            trace!(
                "find_value iteration {}: querying {} nodes in parallel",
                iterations,
                nodes_to_query.len()
            );

            // Query nodes in parallel using tokio::join
            let futures: Vec<_> = nodes_to_query
                .iter()
                .map(|node| self.query_find_value(node, key, k))
                .collect();

            let results = futures::future::join_all(futures).await;

            // Process results
            for (node, result) in nodes_to_query.iter().zip(results.into_iter()) {
                let node_id = node.node_id();

                match result {
                    Ok(DhtValueResult::Found(value)) => {
                        // Verify the value
                        if let Err(e) = value.verify_signature() {
                            warn!("Found value with invalid signature: {}", e);
                            continue;
                        }

                        // Check if expired
                        if value.is_expired() {
                            debug!("Found expired value, continuing search");
                            continue;
                        }

                        // Update routing table
                        let mut table = self.routing_table.write().await;
                        table.touch(&node_id);
                        drop(table);

                        return Ok(DhtValueResult::Found(value));
                    }
                    Ok(DhtValueResult::NotFound(nodes)) => {
                        // Add new nodes to candidates
                        for new_node in nodes {
                            if visited.contains(&new_node.node_id()) {
                                continue;
                            }

                            // Verify node signature
                            if let Err(e) = new_node.verify_signature() {
                                debug!("Ignoring node with invalid signature: {}", e);
                                continue;
                            }

                            // Add to routing table and candidates
                            self.add_node(new_node.clone()).await;
                            candidates.push(new_node);
                        }

                        // Update routing table
                        let mut table = self.routing_table.write().await;
                        table.touch(&node_id);
                        drop(table);
                    }
                    Err(e) => {
                        debug!("Failed to query node: {}", e);
                        let mut table = self.routing_table.write().await;
                        table.record_failure(&node_id);
                        drop(table);
                    }
                }
            }

            // Re-sort candidates by distance
            candidates.sort_by(|a, b| compare_distance(key, &a.node_id(), &b.node_id()));
        }

        // Return the closest nodes we found
        let closest: Vec<DhtNode> = candidates.into_iter().take(k as usize).collect();
        Ok(DhtValueResult::NotFound(closest))
    }

    /// Finds nodes closest to a key.
    ///
    /// Uses parallel queries with alpha concurrent requests (default 3).
    ///
    /// Reference: ton-blockchain/ton/dht/dht-query.cpp (DhtQuery with alpha parameter)
    pub async fn find_nodes(&self, key: &[u8; 32], k: u8) -> Result<Vec<DhtNode>> {
        let mut visited = HashSet::new();

        // Get initial candidates from routing table
        let table = self.routing_table.read().await;
        let mut candidates: Vec<DhtNode> = table.closest_nodes(key, k as usize);
        drop(table);

        // Sort by distance to key
        candidates.sort_by(|a, b| compare_distance(key, &a.node_id(), &b.node_id()));

        let mut iterations = 0;

        while !candidates.is_empty() && iterations < MAX_ITERATIONS {
            iterations += 1;

            // Get the next alpha unvisited nodes for parallel queries
            // (Official TON uses alpha=3 for concurrent queries)
            let nodes_to_query: Vec<DhtNode> = candidates
                .iter()
                .filter(|n| !visited.contains(&n.node_id()))
                .take(self.alpha)
                .cloned()
                .collect();

            if nodes_to_query.is_empty() {
                break;
            }

            // Mark as visited
            for node in &nodes_to_query {
                visited.insert(node.node_id());
            }

            trace!(
                "find_nodes iteration {}: querying {} nodes in parallel",
                iterations,
                nodes_to_query.len()
            );

            // Query nodes in parallel
            let futures: Vec<_> = nodes_to_query
                .iter()
                .map(|node| self.query_find_node(node, key, k))
                .collect();

            let results = futures::future::join_all(futures).await;

            // Process results
            for (node, result) in nodes_to_query.iter().zip(results.into_iter()) {
                let node_id = node.node_id();

                match result {
                    Ok(nodes) => {
                        for new_node in nodes {
                            if visited.contains(&new_node.node_id()) {
                                continue;
                            }

                            // Verify node signature
                            if let Err(e) = new_node.verify_signature() {
                                debug!("Ignoring node with invalid signature: {}", e);
                                continue;
                            }

                            // Add to routing table and candidates
                            self.add_node(new_node.clone()).await;
                            candidates.push(new_node);
                        }

                        // Update routing table
                        let mut table = self.routing_table.write().await;
                        table.touch(&node_id);
                        drop(table);
                    }
                    Err(e) => {
                        debug!("Failed to query node: {}", e);
                        let mut table = self.routing_table.write().await;
                        table.record_failure(&node_id);
                        drop(table);
                    }
                }
            }

            // Re-sort candidates by distance
            candidates.sort_by(|a, b| compare_distance(key, &a.node_id(), &b.node_id()));
        }

        // Return the k closest nodes
        candidates.truncate(k as usize);
        Ok(candidates)
    }

    /// Stores a value in the DHT.
    ///
    /// The value is stored on the k closest nodes to the key.
    /// This method is for local values (values we're storing from this node).
    pub async fn store(&self, value: DhtValue) -> Result<()> {
        // Verify the value before storing (basic verification for local values)
        value.verify_signature()?;

        // Find the closest nodes to store on
        let key = &value.key.key.id;
        let nodes = self.find_nodes(key, DEFAULT_K).await?;

        if nodes.is_empty() {
            return Err(DhtError::NodeNotFound("no nodes found to store value".into()));
        }

        let mut success_count = 0;

        // Store on each node
        for node in nodes {
            match self.store_on_node(&node, &value).await {
                Ok(()) => {
                    success_count += 1;
                    debug!("Stored value on node {:?}", hex::encode(&node.node_id()[..8]));
                }
                Err(e) => {
                    debug!("Failed to store on node: {}", e);
                }
            }
        }

        if success_count == 0 {
            return Err(DhtError::NoResponse);
        }

        debug!(
            "Successfully stored value on {} nodes",
            success_count
        );
        Ok(())
    }

    /// Stores a value received from a remote node after validating it.
    ///
    /// This method validates the incoming value using comprehensive checks:
    /// - Checks value size doesn't exceed limits
    /// - Verifies key description signature
    /// - Verifies value signature based on update rule
    /// - Validates TTL is reasonable
    ///
    /// This should be called when receiving store requests from other DHT nodes.
    pub async fn store_remote_value(&self, value: DhtValue) -> Result<()> {
        let validator = ValueValidator::new();
        validator.validate_incoming_value(&value)?;

        // If validation passes, the value is safe to store
        debug!(
            "Remote value passed validation: key={}, size={}",
            hex::encode(&value.key.key.id[..8]),
            value.value.len()
        );

        // Note: Actual storage in routing table would be implemented in a separate
        // method that interacts with the storage layer.
        Ok(())
    }

    /// Queries a node for a value.
    async fn query_find_value(&self, node: &DhtNode, key: &[u8; 32], k: u8) -> Result<DhtValueResult> {
        let mut query = TlWriter::new();
        query.write_u32(DHT_FIND_VALUE);
        query.write_int256(key);
        query.write_i32(k as i32);

        let response = self.query_node(node, &query.finish()).await?;

        let mut reader = TlReader::new(&response);
        let schema = reader.read_u32()?;

        match schema {
            DHT_VALUE_FOUND => {
                let value = DhtValue::from_tl(reader.remaining())?;
                Ok(DhtValueResult::Found(value))
            }
            DHT_VALUE_NOT_FOUND => {
                let nodes = DhtNodes::from_tl(&response[4..])?;
                Ok(DhtValueResult::NotFound(nodes.nodes))
            }
            _ => Err(DhtError::TlError(format!(
                "unexpected response schema: 0x{:08x}",
                schema
            ))),
        }
    }

    /// Queries a node for other nodes.
    async fn query_find_node(&self, node: &DhtNode, key: &[u8; 32], k: u8) -> Result<Vec<DhtNode>> {
        let mut query = TlWriter::new();
        query.write_u32(DHT_FIND_NODE);
        query.write_int256(key);
        query.write_i32(k as i32);

        let response = self.query_node(node, &query.finish()).await?;

        let mut reader = TlReader::new(&response);
        let schema = reader.read_u32()?;

        if schema != DHT_NODES {
            return Err(DhtError::TlError(format!(
                "expected dht.nodes (0x{:08x}), got 0x{:08x}",
                DHT_NODES, schema
            )));
        }

        let nodes = DhtNodes::from_tl(&response)?;
        Ok(nodes.nodes)
    }

    /// Stores a value on a specific node.
    async fn store_on_node(&self, node: &DhtNode, value: &DhtValue) -> Result<()> {
        let mut query = TlWriter::new();
        query.write_u32(DHT_STORE);
        query.write_raw(&value.to_tl());

        let response = self.query_node(node, &query.finish()).await?;

        let mut reader = TlReader::new(&response);
        let schema = reader.read_u32()?;

        if schema != DHT_STORED {
            return Err(DhtError::TlError(format!(
                "expected dht.stored (0x{:08x}), got 0x{:08x}",
                DHT_STORED, schema
            )));
        }

        Ok(())
    }

    /// Handles a store query from a remote node.
    ///
    /// When another DHT node sends us a store request, we validate the value
    /// before accepting it. This method:
    /// 1. Validates the incoming value using comprehensive security checks
    /// 2. Returns an error if validation fails
    /// 3. Would store the value in the routing table if validation passes
    ///
    /// In a full implementation, this would be called by the DHT query handler.
    #[allow(dead_code)]
    async fn handle_store_query(&self, value: &DhtValue) -> Result<()> {
        let validator = ValueValidator::new();

        // Validate the incoming value
        validator.validate_incoming_value(value)?;

        debug!(
            "Store query validation passed: key={}, size={}",
            hex::encode(&value.key.key.id[..8]),
            value.value.len()
        );

        // Note: In a full implementation, we would:
        // 1. Store the value in a local store
        // 2. Update the routing table
        // This is implemented in the actual DHT network handler.

        Ok(())
    }

    /// Sends a query to a node and waits for a response.
    async fn query_node(&self, node: &DhtNode, query: &[u8]) -> Result<Vec<u8>> {
        let addr = node.first_addr().ok_or_else(|| {
            DhtError::InvalidNode("node has no addresses".into())
        })?;

        let mut adnl = self.adnl.write().await;

        // Add peer if not already added
        adnl.add_peer(addr, &node.id).await?;

        let peer_id = adnl.get_peer_id(&node.id);
        let response = adnl.send_query(&peer_id, query).await?;

        Ok(response)
    }

    /// Returns the number of nodes in the routing table.
    pub async fn routing_table_size(&self) -> usize {
        let table = self.routing_table.read().await;
        table.len()
    }

    /// Returns all nodes in the routing table.
    pub async fn all_nodes(&self) -> Vec<DhtNode> {
        let table = self.routing_table.read().await;
        table.all_nodes()
    }

    /// Performs maintenance on the routing table.
    pub async fn maintenance(&self) {
        let mut table = self.routing_table.write().await;
        table.cleanup();
    }

    /// Returns routing table statistics.
    pub async fn stats(&self) -> crate::routing::RoutingTableStats {
        let table = self.routing_table.read().await;
        table.stats()
    }

    /// Initializes bootstrap with the given bootstrap nodes.
    pub async fn init_bootstrap(&self, bootstrap_nodes: Vec<DhtNode>) -> Result<()> {
        let mut manager = self.bootstrap_manager.write().await;
        *manager = BootstrapManager::new(bootstrap_nodes);
        Ok(())
    }

    /// Performs bootstrap to discover DHT nodes.
    ///
    /// This queries bootstrap nodes to discover other peers and populate
    /// the local routing table. Should be called once after initialization.
    pub async fn bootstrap(&self) -> Result<usize> {
        let local_id = self.local_id;
        let mut manager = self.bootstrap_manager.write().await;

        // Create a query function that calls find_nodes internally
        let mut discovered = 0;

        for _node in manager.bootstrap_nodes().to_vec() {
            match self.find_nodes(&local_id, DEFAULT_K).await {
                Ok(nodes) => {
                    for new_node in nodes {
                        self.add_node(new_node).await;
                        discovered += 1;
                    }
                }
                Err(e) => {
                    debug!("Failed to query bootstrap node: {}", e);
                    continue;
                }
            }
        }

        manager.mark_completed();
        debug!("Bootstrap completed, discovered {} nodes", discovered);
        Ok(discovered)
    }

    /// Starts the background TTL eviction task.
    ///
    /// This task periodically evicts expired DHT values from the routing table.
    /// It runs on a 5-minute interval.
    fn start_background_eviction_task(&self) {
        let routing_table = Arc::clone(&self.routing_table);

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(300)); // 5 minutes
            loop {
                interval.tick().await;
                let mut table = routing_table.write().await;
                table.evict_expired_values();
                debug!("Background eviction task completed");
            }
        });
    }

    /// Returns whether bootstrap has been completed.
    pub async fn is_bootstrapped(&self) -> bool {
        let manager = self.bootstrap_manager.read().await;
        manager.is_completed()
    }
}

/// Hex encoding helper (for debugging).
mod hex {
    pub fn encode(data: &[u8]) -> String {
        data.iter().map(|b| format!("{:02x}", b)).collect()
    }
}

impl std::fmt::Debug for DhtClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DhtClient")
            .field("local_id", &hex::encode(&self.local_id[..8]))
            .field("timeout", &self.timeout)
            .field("alpha", &self.alpha)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ton_crypto::Ed25519Keypair;

    #[tokio::test]
    async fn test_compute_local_id() {
        let keypair = Ed25519Keypair::generate();
        let id = DhtClient::compute_local_id(&keypair.public_key);
        assert_eq!(id.len(), 32);

        // Should be deterministic
        let id2 = DhtClient::compute_local_id(&keypair.public_key);
        assert_eq!(id, id2);
    }

    #[test]
    fn test_default_alpha() {
        // Verify alpha=3 matches official TON DhtMember::default_a()
        // Reference: ton-blockchain/ton/dht/dht.hpp
        assert_eq!(DEFAULT_ALPHA, 3);
    }

    #[test]
    fn test_default_k() {
        // Verify k=10 is the default Kademlia k parameter
        assert_eq!(DEFAULT_K, 10);
    }

    // Note: Full integration tests require a running ADNL node and DHT network.
    // These tests verify the basic structure and logic.
}
