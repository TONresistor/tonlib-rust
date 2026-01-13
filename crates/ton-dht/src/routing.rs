//! Kademlia routing table implementation.
//!
//! The routing table organizes known DHT nodes into 256 k-buckets based on
//! their XOR distance from the local node. Each bucket stores nodes with
//! distances in the range [2^i, 2^(i+1)-1] from the local node.
//!
//! This implementation follows the standard Kademlia protocol with:
//! - 256 buckets (for 256-bit node IDs)
//! - Configurable bucket size (default: 10 nodes)
//! - Replacement cache for candidate nodes

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use crate::distance::{compare_distance, xor_distance};
use crate::node::DhtNode;

/// Default maximum number of nodes per bucket.
pub const DEFAULT_BUCKET_SIZE: usize = 10;

/// Default maximum number of candidates per bucket.
pub const DEFAULT_CANDIDATE_SIZE: usize = 10;

/// Default ping interval for considering a node stale (60 seconds).
pub const DEFAULT_PING_INTERVAL: Duration = Duration::from_secs(60);

/// A k-bucket storing nodes at a specific distance range.
#[derive(Debug)]
pub struct Bucket {
    /// Active nodes in this bucket (sorted by last seen, oldest first).
    nodes: VecDeque<BucketEntry>,
    /// Candidate nodes waiting to replace stale nodes.
    candidates: VecDeque<BucketEntry>,
    /// Maximum number of active nodes.
    max_nodes: usize,
    /// Maximum number of candidates.
    max_candidates: usize,
}

/// An entry in a bucket.
#[derive(Debug, Clone)]
pub struct BucketEntry {
    /// The DHT node.
    pub node: DhtNode,
    /// The node's ID (SHA256 of TL-serialized public key).
    pub node_id: [u8; 32],
    /// When the node was last seen.
    pub last_seen: Instant,
    /// Number of failed queries to this node.
    pub failures: u32,
    /// Time of last successful ping.
    pub last_ping_at: Instant,
    /// Interval for considering node stale.
    pub ping_interval: Duration,
}

impl BucketEntry {
    /// Creates a new bucket entry.
    pub fn new(node: DhtNode) -> Self {
        Self::with_ping_interval(node, DEFAULT_PING_INTERVAL)
    }

    /// Creates a new bucket entry with a custom ping interval.
    pub fn with_ping_interval(node: DhtNode, ping_interval: Duration) -> Self {
        let node_id = node.node_id();
        let now = Instant::now();
        Self {
            node,
            node_id,
            last_seen: now,
            failures: 0,
            last_ping_at: now,
            ping_interval,
        }
    }

    /// Updates the last seen time.
    pub fn touch(&mut self) {
        self.last_seen = Instant::now();
        self.failures = 0;
    }

    /// Records a failure.
    pub fn record_failure(&mut self) {
        self.failures += 1;
    }

    /// Updates the last ping time to the current time.
    pub fn update_last_ping(&mut self) {
        self.last_ping_at = Instant::now();
    }

    /// Returns true if the node is considered stale based on time since last ping.
    ///
    /// A node is stale if the time elapsed since the last successful ping
    /// exceeds the configured ping interval.
    pub fn is_stale(&self) -> bool {
        self.last_ping_at.elapsed() > self.ping_interval
    }
}

impl Bucket {
    /// Creates a new empty bucket.
    pub fn new() -> Self {
        Self::with_capacity(DEFAULT_BUCKET_SIZE, DEFAULT_CANDIDATE_SIZE)
    }

    /// Creates a new bucket with custom capacity.
    pub fn with_capacity(max_nodes: usize, max_candidates: usize) -> Self {
        Self {
            nodes: VecDeque::with_capacity(max_nodes),
            candidates: VecDeque::with_capacity(max_candidates),
            max_nodes,
            max_candidates,
        }
    }

    /// Returns the number of active nodes.
    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    /// Returns true if the bucket has no active nodes.
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    /// Returns true if the bucket is full.
    pub fn is_full(&self) -> bool {
        self.nodes.len() >= self.max_nodes
    }

    /// Returns all active nodes.
    pub fn nodes(&self) -> impl Iterator<Item = &BucketEntry> {
        self.nodes.iter()
    }

    /// Returns all candidate nodes.
    pub fn candidates(&self) -> impl Iterator<Item = &BucketEntry> {
        self.candidates.iter()
    }

    /// Finds a node by its ID.
    pub fn find(&self, node_id: &[u8; 32]) -> Option<&BucketEntry> {
        self.nodes.iter().find(|e| &e.node_id == node_id)
    }

    /// Finds a mutable reference to a node by its ID.
    pub fn find_mut(&mut self, node_id: &[u8; 32]) -> Option<&mut BucketEntry> {
        self.nodes.iter_mut().find(|e| &e.node_id == node_id)
    }

    /// Adds or updates a node in the bucket.
    ///
    /// Returns true if the node was added, false if the bucket was full.
    pub fn add(&mut self, node: DhtNode) -> bool {
        let node_id = node.node_id();

        // Check if node already exists
        if let Some(entry) = self.find_mut(&node_id) {
            // Update existing node
            if node.version >= entry.node.version {
                entry.node = node;
            }
            entry.touch();
            return true;
        }

        // Bucket not full - add directly
        if !self.is_full() {
            self.nodes.push_back(BucketEntry::new(node));
            return true;
        }

        // Bucket full - check for stale nodes
        if let Some(pos) = self.nodes.iter().position(|e| e.is_stale()) {
            self.nodes.remove(pos);
            self.nodes.push_back(BucketEntry::new(node));
            return true;
        }

        // Add to candidates instead
        self.add_candidate(node);
        false
    }

    /// Adds a node to the candidate list.
    fn add_candidate(&mut self, node: DhtNode) {
        let node_id = node.node_id();

        // Check if already a candidate
        if let Some(entry) = self.candidates.iter_mut().find(|e| e.node_id == node_id) {
            if node.version >= entry.node.version {
                entry.node = node;
            }
            entry.touch();
            return;
        }

        // Add to candidates
        if self.candidates.len() >= self.max_candidates {
            self.candidates.pop_front();
        }
        self.candidates.push_back(BucketEntry::new(node));
    }

    /// Removes a node from the bucket.
    pub fn remove(&mut self, node_id: &[u8; 32]) -> Option<DhtNode> {
        if let Some(pos) = self.nodes.iter().position(|e| &e.node_id == node_id) {
            let entry = self.nodes.remove(pos)?;

            // Promote a candidate if available
            if let Some(candidate) = self.candidates.pop_front() {
                self.nodes.push_back(candidate);
            }

            return Some(entry.node);
        }
        None
    }

    /// Marks a node as seen (updates last_seen).
    pub fn touch(&mut self, node_id: &[u8; 32]) {
        if let Some(entry) = self.find_mut(node_id) {
            entry.touch();
        }
    }

    /// Records a failure for a node.
    pub fn record_failure(&mut self, node_id: &[u8; 32]) {
        if let Some(entry) = self.find_mut(node_id) {
            entry.record_failure();
        }
    }

    /// Returns the oldest node (for ping checking).
    pub fn oldest(&self) -> Option<&BucketEntry> {
        self.nodes.front()
    }

    /// Clears stale nodes and promotes candidates.
    pub fn cleanup(&mut self) {
        // Remove stale nodes
        self.nodes.retain(|e| !e.is_stale());

        // Promote candidates
        while !self.is_full() {
            if let Some(candidate) = self.candidates.pop_front() {
                self.nodes.push_back(candidate);
            } else {
                break;
            }
        }
    }
}

impl Default for Bucket {
    fn default() -> Self {
        Self::new()
    }
}

/// The Kademlia routing table.
///
/// Organizes DHT nodes into 256 k-buckets based on XOR distance.
#[derive(Debug)]
pub struct RoutingTable {
    /// Our local node ID.
    local_id: [u8; 32],
    /// The 256 k-buckets.
    buckets: Vec<Bucket>,
    /// Maximum nodes per bucket.
    bucket_size: usize,
}

impl RoutingTable {
    /// Creates a new routing table.
    pub fn new(local_id: [u8; 32]) -> Self {
        Self::with_bucket_size(local_id, DEFAULT_BUCKET_SIZE)
    }

    /// Creates a new routing table with custom bucket size.
    pub fn with_bucket_size(local_id: [u8; 32], bucket_size: usize) -> Self {
        let mut buckets = Vec::with_capacity(256);
        for _ in 0..256 {
            buckets.push(Bucket::with_capacity(bucket_size, DEFAULT_CANDIDATE_SIZE));
        }
        Self {
            local_id,
            buckets,
            bucket_size,
        }
    }

    /// Returns our local node ID.
    pub fn local_id(&self) -> &[u8; 32] {
        &self.local_id
    }

    /// Calculates which bucket a node belongs to based on XOR distance.
    pub fn bucket_index(&self, node_id: &[u8; 32]) -> usize {
        let distance = xor_distance(&self.local_id, node_id);
        distance.bucket_index()
    }

    /// Returns a reference to a bucket.
    pub fn bucket(&self, index: usize) -> Option<&Bucket> {
        self.buckets.get(index)
    }

    /// Returns a mutable reference to a bucket.
    pub fn bucket_mut(&mut self, index: usize) -> Option<&mut Bucket> {
        self.buckets.get_mut(index)
    }

    /// Adds a node to the routing table.
    ///
    /// Returns true if the node was added, false if the bucket was full.
    pub fn add(&mut self, node: DhtNode) -> bool {
        let node_id = node.node_id();

        // Don't add ourselves
        if node_id == self.local_id {
            return false;
        }

        let bucket_idx = self.bucket_index(&node_id);
        self.buckets[bucket_idx].add(node)
    }

    /// Removes a node from the routing table.
    pub fn remove(&mut self, node_id: &[u8; 32]) -> Option<DhtNode> {
        let bucket_idx = self.bucket_index(node_id);
        self.buckets[bucket_idx].remove(node_id)
    }

    /// Finds a node by its ID.
    pub fn find(&self, node_id: &[u8; 32]) -> Option<&DhtNode> {
        let bucket_idx = self.bucket_index(node_id);
        self.buckets[bucket_idx].find(node_id).map(|e| &e.node)
    }

    /// Updates a node's last seen time.
    pub fn touch(&mut self, node_id: &[u8; 32]) {
        let bucket_idx = self.bucket_index(node_id);
        self.buckets[bucket_idx].touch(node_id);
    }

    /// Records a failure for a node.
    pub fn record_failure(&mut self, node_id: &[u8; 32]) {
        let bucket_idx = self.bucket_index(node_id);
        self.buckets[bucket_idx].record_failure(node_id);
    }

    /// Returns the k closest nodes to a target key.
    ///
    /// Nodes are sorted by XOR distance to the target.
    pub fn closest_nodes(&self, target: &[u8; 32], k: usize) -> Vec<DhtNode> {
        let mut nodes: Vec<_> = self
            .buckets
            .iter()
            .flat_map(|b| b.nodes())
            .map(|e| (e.node.clone(), e.node_id))
            .collect();

        // Sort by distance to target
        nodes.sort_by(|(_, id_a), (_, id_b)| compare_distance(target, id_a, id_b));

        // Take the k closest
        nodes.into_iter().take(k).map(|(node, _)| node).collect()
    }

    /// Returns the total number of nodes in the routing table.
    pub fn len(&self) -> usize {
        self.buckets.iter().map(|b| b.len()).sum()
    }

    /// Returns true if the routing table is empty.
    pub fn is_empty(&self) -> bool {
        self.buckets.iter().all(|b| b.is_empty())
    }

    /// Returns all nodes in the routing table.
    pub fn all_nodes(&self) -> Vec<DhtNode> {
        self.buckets
            .iter()
            .flat_map(|b| b.nodes())
            .map(|e| e.node.clone())
            .collect()
    }

    /// Performs cleanup on all buckets.
    pub fn cleanup(&mut self) {
        for bucket in &mut self.buckets {
            bucket.cleanup();
        }
    }

    /// Evicts expired DHT values from the routing table.
    ///
    /// This method would be called periodically to remove values
    /// whose TTL has expired. Currently this is a placeholder for
    /// future value storage in the routing table.
    pub fn evict_expired_values(&mut self) {
        // Note: Currently, the routing table only stores nodes, not values.
        // When value storage is implemented in the routing table,
        // this method would iterate through stored values and remove expired ones.
        // For now, this is a no-op that allows the background task to function.
    }

    /// Returns statistics about the routing table.
    pub fn stats(&self) -> RoutingTableStats {
        let mut non_empty_buckets = 0;
        let mut total_nodes = 0;
        let mut total_candidates = 0;

        for bucket in &self.buckets {
            if !bucket.is_empty() {
                non_empty_buckets += 1;
            }
            total_nodes += bucket.nodes.len();
            total_candidates += bucket.candidates.len();
        }

        RoutingTableStats {
            bucket_size: self.bucket_size,
            non_empty_buckets,
            total_nodes,
            total_candidates,
        }
    }
}

/// Statistics about the routing table.
#[derive(Debug, Clone)]
pub struct RoutingTableStats {
    /// Maximum nodes per bucket.
    pub bucket_size: usize,
    /// Number of non-empty buckets.
    pub non_empty_buckets: usize,
    /// Total number of active nodes.
    pub total_nodes: usize,
    /// Total number of candidate nodes.
    pub total_candidates: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node::AdnlAddressList;
    use std::net::Ipv4Addr;
    use ton_crypto::Ed25519Keypair;

    fn create_test_node() -> DhtNode {
        let keypair = Ed25519Keypair::generate();
        let addr = crate::node::AdnlAddress::udp(Ipv4Addr::new(127, 0, 0, 1), 30303);
        let addr_list = AdnlAddressList::with_address(addr);
        DhtNode::with_current_version(keypair.public_key, addr_list)
    }

    fn create_node_with_id(id_byte: u8) -> DhtNode {
        let mut id = [0u8; 32];
        id[0] = id_byte;
        let addr_list = AdnlAddressList::new();
        DhtNode::new(id, addr_list, 0)
    }

    #[test]
    fn test_bucket_add() {
        let mut bucket = Bucket::new();
        let node = create_test_node();
        let node_id = node.node_id();

        assert!(bucket.add(node));
        assert_eq!(bucket.len(), 1);
        assert!(bucket.find(&node_id).is_some());
    }

    #[test]
    fn test_bucket_full() {
        let mut bucket = Bucket::with_capacity(2, 2);

        let node1 = create_test_node();
        let node2 = create_test_node();
        let node3 = create_test_node();

        assert!(bucket.add(node1));
        assert!(bucket.add(node2));
        assert!(!bucket.add(node3)); // Added to candidates

        assert_eq!(bucket.len(), 2);
        assert!(bucket.is_full());
    }

    #[test]
    fn test_bucket_remove_and_promote() {
        let mut bucket = Bucket::with_capacity(2, 2);

        let node1 = create_test_node();
        let node2 = create_test_node();
        let node3 = create_test_node();

        let id1 = node1.node_id();

        bucket.add(node1);
        bucket.add(node2);
        bucket.add(node3); // Goes to candidates

        assert_eq!(bucket.len(), 2);

        // Remove node1, node3 should be promoted
        bucket.remove(&id1);
        assert_eq!(bucket.len(), 2); // Candidate promoted
    }

    #[test]
    fn test_routing_table_add() {
        let local_keypair = Ed25519Keypair::generate();
        let mut writer = crate::tl::TlWriter::new();
        writer.write_u32(crate::tl::PUB_ED25519);
        writer.write_int256(&local_keypair.public_key);
        let local_id = ton_crypto::sha256::sha256(&writer.finish());

        let mut table = RoutingTable::new(local_id);
        let node = create_test_node();

        assert!(table.add(node));
        assert_eq!(table.len(), 1);
    }

    #[test]
    fn test_routing_table_closest() {
        let local_id = [0u8; 32];
        let mut table = RoutingTable::new(local_id);

        // Add nodes with different distances
        for i in 1..10 {
            let node = create_node_with_id(i);
            table.add(node);
        }

        let target = [1u8; 32];
        let closest = table.closest_nodes(&target, 3);

        assert_eq!(closest.len(), 3);
    }

    #[test]
    fn test_bucket_index() {
        let local_id = [0u8; 32];
        let table = RoutingTable::new(local_id);

        // TON bucket assignment: bucket_index = count_leading_zeroes(XOR_distance)
        // More leading zeros = closer node = higher bucket number

        // Distance 1 (last bit set) -> 255 leading zeros -> bucket 255 (closest)
        let mut id1 = [0u8; 32];
        id1[31] = 0x01;
        assert_eq!(table.bucket_index(&id1), 255);

        // Distance 128 (bit 7 set) -> 248 leading zeros -> bucket 248
        let mut id2 = [0u8; 32];
        id2[31] = 0x80;
        assert_eq!(table.bucket_index(&id2), 248);

        // Distance in second-to-last byte -> 247 leading zeros -> bucket 247
        let mut id3 = [0u8; 32];
        id3[30] = 0x01;
        assert_eq!(table.bucket_index(&id3), 247);

        // Distance 2^255 (MSB set) -> 0 leading zeros -> bucket 0 (farthest)
        let mut id4 = [0u8; 32];
        id4[0] = 0x80;
        assert_eq!(table.bucket_index(&id4), 0);
    }

    #[test]
    fn test_routing_table_stats() {
        let local_id = [0u8; 32];
        let mut table = RoutingTable::new(local_id);

        let stats = table.stats();
        assert_eq!(stats.total_nodes, 0);
        assert_eq!(stats.non_empty_buckets, 0);

        for i in 1..5 {
            let node = create_node_with_id(i);
            table.add(node);
        }

        let stats = table.stats();
        assert_eq!(stats.total_nodes, 4);
        assert!(stats.non_empty_buckets > 0);
    }

    #[test]
    fn test_bucket_entry_stale() {
        let node = create_test_node();
        // Create entry with very short ping interval for testing
        let mut entry = BucketEntry::with_ping_interval(node, Duration::from_millis(10));

        // Initially not stale (just created)
        assert!(!entry.is_stale());

        // Wait for the ping interval to elapse
        std::thread::sleep(Duration::from_millis(20));

        // Now should be stale
        assert!(entry.is_stale());

        // Update last ping time
        entry.update_last_ping();

        // Should no longer be stale
        assert!(!entry.is_stale());
    }

    #[test]
    fn test_bucket_entry_ping_interval_default() {
        let node = create_test_node();
        let entry = BucketEntry::new(node);

        // Default ping interval should be 60 seconds
        assert_eq!(entry.ping_interval, Duration::from_secs(60));

        // Initially not stale
        assert!(!entry.is_stale());
    }

    #[test]
    fn test_bucket_entry_custom_ping_interval() {
        let node = create_test_node();
        let custom_interval = Duration::from_secs(120);
        let entry = BucketEntry::with_ping_interval(node, custom_interval);

        assert_eq!(entry.ping_interval, custom_interval);
        assert!(!entry.is_stale());
    }
}
