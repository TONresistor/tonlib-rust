//! Bootstrap manager for DHT network initialization.
//!
//! The bootstrap manager handles the initial bootstrap process that allows
//! a new DHT node to join the network by learning about other nodes from
//! a set of well-known bootstrap nodes.

use tracing::{debug, warn};

use crate::error::Result;
use crate::node::DhtNode;

/// Bootstrap manager for DHT network initialization.
///
/// Handles the bootstrap process by querying bootstrap nodes to discover
/// other peers and populate the local routing table.
#[derive(Debug, Clone)]
pub struct BootstrapManager {
    /// List of bootstrap nodes to query.
    bootstrap_nodes: Vec<DhtNode>,
    /// Whether bootstrap has been completed.
    completed: bool,
}

impl BootstrapManager {
    /// Creates a new bootstrap manager with the given bootstrap nodes.
    pub fn new(bootstrap_nodes: Vec<DhtNode>) -> Self {
        Self {
            bootstrap_nodes,
            completed: false,
        }
    }

    /// Creates an empty bootstrap manager (useful for testing).
    pub fn empty() -> Self {
        Self {
            bootstrap_nodes: Vec::new(),
            completed: false,
        }
    }

    /// Returns the bootstrap nodes.
    pub fn bootstrap_nodes(&self) -> &[DhtNode] {
        &self.bootstrap_nodes
    }

    /// Returns whether bootstrap has been completed.
    pub fn is_completed(&self) -> bool {
        self.completed
    }

    /// Marks bootstrap as completed.
    pub fn mark_completed(&mut self) {
        self.completed = true;
    }

    /// Performs bootstrap by querying bootstrap nodes.
    ///
    /// For each bootstrap node:
    /// 1. Query it with find_node for our own node ID
    /// 2. Collect returned nodes
    /// 3. Add them to the routing table
    /// 4. Continue until enough nodes are discovered
    pub async fn bootstrap<F>(&mut self, local_id: &[u8; 32], mut query_fn: F) -> Result<usize>
    where
        F: FnMut(&DhtNode) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<Vec<DhtNode>>> + Send>,
        > + Send,
    {
        if self.bootstrap_nodes.is_empty() {
            debug!("No bootstrap nodes configured");
            return Ok(0);
        }

        let mut discovered_nodes = Vec::new();
        let mut queried_nodes = std::collections::HashSet::new();

        debug!(
            "Starting bootstrap with {} bootstrap nodes",
            self.bootstrap_nodes.len()
        );

        // Query each bootstrap node
        for bootstrap_node in &self.bootstrap_nodes {
            let node_id = bootstrap_node.node_id();

            if queried_nodes.contains(&node_id) {
                continue;
            }
            queried_nodes.insert(node_id);

            debug!(
                "Bootstrapping from node {:?}",
                hex::encode(&node_id[..8])
            );

            // Query the bootstrap node for nodes closest to our ID
            match query_fn(bootstrap_node).await {
                Ok(nodes) => {
                    debug!("Bootstrap node returned {} peers", nodes.len());

                    for node in nodes {
                        let new_node_id = node.node_id();

                        // Skip if we already know about this node
                        if discovered_nodes.iter().any(|n: &DhtNode| n.node_id() == new_node_id)
                            || queried_nodes.contains(&new_node_id)
                            || new_node_id == *local_id
                        {
                            continue;
                        }

                        discovered_nodes.push(node);
                    }
                }
                Err(e) => {
                    warn!(
                        "Failed to bootstrap from node {:?}: {}",
                        hex::encode(&node_id[..8]),
                        e
                    );
                    // Continue with next bootstrap node
                    continue;
                }
            }
        }

        let count = discovered_nodes.len();
        self.completed = true;

        debug!("Bootstrap completed, discovered {} nodes", count);
        Ok(count)
    }
}

/// Hex encoding helper (for debugging).
mod hex {
    pub fn encode(data: &[u8]) -> String {
        data.iter().map(|b| format!("{:02x}", b)).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ton_crypto::Ed25519Keypair;

    fn create_test_node() -> DhtNode {
        let keypair = Ed25519Keypair::generate();
        let addr = crate::node::AdnlAddress::udp(std::net::Ipv4Addr::new(127, 0, 0, 1), 30303);
        let addr_list = crate::node::AdnlAddressList::with_address(addr);
        DhtNode::with_current_version(keypair.public_key, addr_list)
    }

    #[test]
    fn test_bootstrap_manager_creation() {
        let nodes = vec![create_test_node()];
        let manager = BootstrapManager::new(nodes.clone());

        assert_eq!(manager.bootstrap_nodes().len(), 1);
        assert!(!manager.is_completed());
    }

    #[test]
    fn test_bootstrap_manager_empty() {
        let manager = BootstrapManager::empty();
        assert_eq!(manager.bootstrap_nodes().len(), 0);
        assert!(!manager.is_completed());
    }

    #[test]
    fn test_bootstrap_manager_mark_completed() {
        let mut manager = BootstrapManager::empty();
        assert!(!manager.is_completed());

        manager.mark_completed();
        assert!(manager.is_completed());
    }

    #[tokio::test]
    async fn test_bootstrap_manager_empty_nodes() {
        let mut manager = BootstrapManager::empty();
        let _local_id = [0u8; 32];

        // Empty bootstrap should mark as completed but return 0 nodes
        assert!(!manager.is_completed());
        manager.mark_completed();
        assert!(manager.is_completed());
    }

    #[tokio::test]
    async fn test_bootstrap_manager_with_nodes() {
        let bootstrap_node = create_test_node();
        let discovered_node = create_test_node();
        let mut manager = BootstrapManager::new(vec![bootstrap_node]);

        let local_id = [0u8; 32];
        let discovered_node_clone = discovered_node.clone();

        let result = manager.bootstrap(&local_id, move |_| {
            let node = discovered_node_clone.clone();
            Box::pin(async move { Ok(vec![node]) })
        }).await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 1);
        assert!(manager.is_completed());
    }
}
