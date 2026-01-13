//! # ton-dht
//!
//! TON DHT (Distributed Hash Table) implementation based on the Kademlia protocol.
//!
//! This crate provides the DHT layer for the TON network, enabling:
//! - Peer discovery and routing
//! - ADNL address resolution
//! - Overlay network node lists
//! - Distributed key-value storage
//!
//! ## Overview
//!
//! The TON DHT is a Kademlia-based distributed hash table with 256-bit node IDs.
//! It uses XOR distance for routing and organizes nodes into 256 k-buckets.
//!
//! ### Key Concepts
//!
//! - **Node ID**: SHA256 hash of the TL-serialized Ed25519 public key
//! - **XOR Distance**: Distance between two nodes = XOR of their IDs
//! - **K-Buckets**: 256 buckets storing nodes at different distance ranges
//! - **Update Rules**: Control who can modify stored values (Signature, Anybody, OverlayNodes)
//!
//! ## Example
//!
//! ```rust,no_run
//! use std::net::SocketAddr;
//! use ton_dht::{DhtClient, DhtKey, DhtKeyDescription, DhtValue, UpdateRule};
//! use ton_adnl::udp::AdnlNode;
//! use ton_crypto::Ed25519Keypair;
//!
//! async fn example() -> Result<(), Box<dyn std::error::Error>> {
//!     // Create an ADNL node
//!     let addr: SocketAddr = "0.0.0.0:30303".parse()?;
//!     let adnl = AdnlNode::bind(addr).await?;
//!
//!     // Create a DHT client
//!     let client = DhtClient::new(adnl);
//!
//!     // Add bootstrap nodes
//!     // client.add_bootstrap_node("1.2.3.4:30303".parse()?, &bootstrap_pubkey).await?;
//!
//!     // Create a key for our ADNL address
//!     let keypair = Ed25519Keypair::generate();
//!     let key = DhtKey::for_address(&keypair.public_key);
//!
//!     // Look up a value
//!     let result = client.find_value(&key.id, 10).await?;
//!
//!     Ok(())
//! }
//! ```
//!
//! ## DHT Operations
//!
//! ### Find Value
//!
//! Searches the DHT for a value associated with a key:
//!
//! ```rust,no_run
//! use ton_dht::{DhtClient, DhtValueResult};
//!
//! async fn find_example(client: &DhtClient) -> Result<(), ton_dht::DhtError> {
//!     let key = [0u8; 32]; // The key to search for
//!
//!     match client.find_value(&key, 10).await? {
//!         DhtValueResult::Found(value) => {
//!             println!("Found value: {} bytes", value.value.len());
//!         }
//!         DhtValueResult::NotFound(closest_nodes) => {
//!             println!("Value not found, {} closest nodes returned", closest_nodes.len());
//!         }
//!     }
//!
//!     Ok(())
//! }
//! ```
//!
//! ### Store Value
//!
//! Stores a value in the DHT:
//!
//! ```rust,no_run
//! use ton_dht::{DhtClient, DhtKey, DhtKeyDescription, DhtValue, UpdateRule};
//! use ton_crypto::Ed25519Keypair;
//!
//! async fn store_example(client: &DhtClient) -> Result<(), ton_dht::DhtError> {
//!     let keypair = Ed25519Keypair::generate();
//!     let key = DhtKey::for_address(&keypair.public_key);
//!
//!     let mut key_desc = DhtKeyDescription::new(
//!         key,
//!         keypair.public_key,
//!         UpdateRule::Signature,
//!     );
//!     key_desc.sign(&keypair);
//!
//!     let mut value = DhtValue::with_ttl_duration(
//!         key_desc,
//!         b"my address data".to_vec(),
//!         3600, // 1 hour TTL
//!     );
//!     value.sign(&keypair);
//!
//!     client.store(value).await?;
//!
//!     Ok(())
//! }
//! ```
//!
//! ## TL Schema
//!
//! The DHT uses TL (Type Language) for message serialization. Key schemas include:
//!
//! ```text
//! dht.key id:int256 name:bytes idx:int = dht.Key
//! dht.keyDescription key:dht.key id:PublicKey update_rule:dht.UpdateRule signature:bytes
//! dht.value key:dht.keyDescription value:bytes ttl:int signature:bytes
//! dht.node id:PublicKey addr_list:adnl.addressList version:int signature:bytes
//!
//! dht.findValue key:int256 k:int = dht.ValueResult
//! dht.findNode key:int256 k:int = dht.Nodes
//! dht.store value:dht.Value = dht.Stored
//! ```

pub mod bootstrap;
pub mod client;
pub mod config;
pub mod distance;
pub mod error;
pub mod key;
pub mod node;
pub mod reverse;
pub mod routing;
pub mod storage;
pub mod tl;
pub mod validation;
pub mod value;

// Re-export main types
pub use bootstrap::BootstrapManager;
pub use client::{DhtClient, DEFAULT_ALPHA, DEFAULT_K, DEFAULT_TIMEOUT, MAX_ITERATIONS};
pub use config::{get_bootstrap_nodes, Network};
pub use distance::{compare_distance, is_closer, xor_distance, Distance};
pub use error::{DhtError, Result};
pub use key::{key_names, DhtKey, DhtKeyDescription};
pub use node::{AdnlAddress, AdnlAddressList, DhtNode, DhtNodes};
pub use reverse::{
    DhtGetSignedAddressList, DhtRegisterReverseConnection, DhtRequestReversePing,
    ReversePingResult, ReverseConnectionManager, ReverseConnectionStats,
};
pub use routing::{Bucket, BucketEntry, RoutingTable, RoutingTableStats, DEFAULT_BUCKET_SIZE};
pub use storage::{DhtKeyId, DhtStorage, DhtStorageStats, StoredValue};
pub use validation::ValueValidator;
pub use value::{DhtValue, DhtValueResult, UpdateRule};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exports() {
        // Verify that key types are accessible
        let _distance = Distance::zero();
        let _err: std::result::Result<(), DhtError> = Err(DhtError::ValueNotFound);
    }

    #[test]
    fn test_xor_distance_basic() {
        let a = [0u8; 32];
        let mut b = [0u8; 32];
        b[31] = 1;

        let dist = xor_distance(&a, &b);
        // Distance 1 (LSB set) = 255 leading zeros → bucket 255 (closest non-self)
        assert_eq!(dist.bucket_index(), 255);
    }

    #[test]
    fn test_update_rules() {
        assert_eq!(
            UpdateRule::Signature.schema_id(),
            tl::DHT_UPDATE_RULE_SIGNATURE
        );
        assert_eq!(UpdateRule::Anybody.schema_id(), tl::DHT_UPDATE_RULE_ANYBODY);
        assert_eq!(
            UpdateRule::OverlayNodes.schema_id(),
            tl::DHT_UPDATE_RULE_OVERLAY_NODES
        );
    }
}
