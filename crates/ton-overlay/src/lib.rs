//! # ton-overlay
//!
//! TON Overlay Network implementation for shardchain communication.
//!
//! Overlay networks enable communication within specific subnetworks (e.g., shardchains).
//! They build on top of ADNL for networking, DHT for peer discovery, and RLDP for
//! reliable large message transfer.
//!
//! ## Overview
//!
//! The TON blockchain uses overlay networks to organize communication between nodes
//! that participate in specific workchains and shards. Each shardchain has its own
//! overlay network where validators and fullnodes exchange:
//!
//! - Block candidates
//! - New external messages
//! - Validator signatures
//! - Other consensus-related data
//!
//! ## Key Concepts
//!
//! - **Overlay ID**: A 256-bit identifier computed from workchain, shard, and zero_state_hash
//! - **Overlay Node**: A participant in an overlay network
//! - **Certificate**: Authorization for sending broadcasts in an overlay
//! - **Broadcast**: A message sent to all nodes in an overlay
//!
//! ## Example: Joining an Overlay
//!
//! ```rust,no_run
//! use std::sync::Arc;
//! use tokio::sync::RwLock;
//! use ton_overlay::{OverlayManager, OverlayId};
//! use ton_adnl::udp::AdnlNode;
//! use ton_crypto::Ed25519Keypair;
//!
//! async fn join_overlay() -> Result<(), Box<dyn std::error::Error>> {
//!     let keypair = Ed25519Keypair::generate();
//!     let adnl = AdnlNode::bind("0.0.0.0:30303".parse()?).await?;
//!     let adnl = Arc::new(RwLock::new(adnl));
//!
//!     let mut manager = OverlayManager::new(keypair, adnl);
//!
//!     // Calculate overlay ID for masterchain
//!     let zero_state_hash = [0u8; 32]; // Replace with actual hash
//!     let overlay_id = OverlayId::for_masterchain(&zero_state_hash);
//!
//!     // Join the overlay
//!     manager.join_overlay(overlay_id).await?;
//!
//!     // Broadcast data
//!     manager.broadcast(overlay_id.as_bytes(), b"Hello overlay!".to_vec()).await?;
//!
//!     Ok(())
//! }
//! ```
//!
//! ## Example: Broadcasting Data
//!
//! ```rust,no_run
//! use ton_overlay::{OverlayBroadcast, OverlayCertificate};
//! use ton_crypto::Ed25519Keypair;
//!
//! fn create_broadcast() {
//!     let keypair = Ed25519Keypair::generate();
//!     let overlay_id = [1u8; 32]; // The overlay we're broadcasting to
//!
//!     // Create a simple broadcast
//!     let mut broadcast = OverlayBroadcast::new(b"Hello overlay!".to_vec());
//!     broadcast.sign(&keypair, &overlay_id);
//!
//!     // Verify the broadcast
//!     assert!(broadcast.verify_signature(&overlay_id).is_ok());
//! }
//! ```
//!
//! ## Example: Using Certificates
//!
//! ```rust
//! use ton_overlay::{CertificateBuilder, OverlayCertificate};
//! use ton_crypto::Ed25519Keypair;
//!
//! fn create_certificate() {
//!     let issuer = Ed25519Keypair::generate();
//!     let node_keypair = Ed25519Keypair::generate();
//!
//!     let overlay_id = [1u8; 32];
//!     let node_id = node_keypair.public_key;
//!
//!     // Create and sign a certificate
//!     let certificate = CertificateBuilder::new(overlay_id, node_id)
//!         .expire_in(3600)  // Valid for 1 hour
//!         .max_size(1024)   // Max 1KB broadcasts
//!         .build(&issuer);
//!
//!     // Verify the certificate
//!     assert!(certificate.verify(&overlay_id, &node_id).is_ok());
//! }
//! ```
//!
//! ## TL Schemas
//!
//! The overlay protocol uses the following TL schemas:
//!
//! ```text
//! overlay.node id:PublicKey overlay:int256 version:int signature:bytes = overlay.Node;
//! overlay.nodes nodes:(vector overlay.node) = overlay.Nodes;
//! overlay.query overlay:int256 = True;
//! overlay.getRandomPeers peers:overlay.nodes = overlay.Nodes;
//! overlay.broadcast src:PublicKey certificate:overlay.Certificate flags:int data:bytes date:int signature:bytes = overlay.Broadcast;
//! overlay.certificate issued_by:PublicKey expire_at:int max_size:int signature:bytes = overlay.Certificate;
//! overlay.emptyCertificate = overlay.Certificate;
//! ```
//!
//! ## Module Structure
//!
//! - `overlay_id`: Overlay ID calculation
//! - `node`: Overlay node management
//! - `certificate`: Certificate validation
//! - `broadcast`: Broadcast handling and propagation
//! - `manager`: Main OverlayManager for joining/leaving overlays
//! - `tl`: TL schema definitions and serialization
//! - `error`: Error types

pub mod broadcast;
pub mod certificate;
pub mod error;
pub mod manager;
pub mod node;
pub mod overlay_id;
pub mod tl;

// Re-export main types
pub use broadcast::{
    Broadcast, BroadcastCache, OverlayBroadcast, OverlayBroadcastFec, OverlayBroadcastFecShort,
    MAX_BROADCAST_AGE, MAX_BROADCAST_SIZE, MAX_FEC_BROADCAST_SIZE,
};
pub use broadcast::flags as broadcast_flags;

pub use certificate::{
    calculate_adnl_short_id, CertificateBuilder, OverlayCertificate, MAX_CERTIFICATE_SIZE,
};

pub use error::{OverlayError, Result};

pub use manager::{
    OverlayConfig, OverlayManager, OverlayState, OverlayStats,
    DEFAULT_BROADCAST_CACHE_SIZE, DEFAULT_DISCOVERY_INTERVAL, DEFAULT_MAX_PEERS,
    DEFAULT_QUERY_TIMEOUT,
};

pub use node::{OverlayNode, OverlayNodes, OverlayPeer};

pub use overlay_id::{calculate_overlay_id, dht_key_for_overlay, OverlayId};

// Re-export TL schema IDs
pub mod schemas {
    //! TL schema IDs for Overlay protocol messages.
    pub use crate::tl::{
        OVERLAY_BROADCAST, OVERLAY_BROADCAST_FEC, OVERLAY_BROADCAST_FEC_CONFIRM,
        OVERLAY_BROADCAST_FEC_SHORT, OVERLAY_BROADCAST_LIST, OVERLAY_BROADCAST_NOT_FOUND,
        OVERLAY_CERTIFICATE, OVERLAY_CERTIFICATE_ID, OVERLAY_EMPTY_CERTIFICATE,
        OVERLAY_FEC_COMPLETED, OVERLAY_FEC_RECEIVED, OVERLAY_GET_RANDOM_PEERS,
        OVERLAY_MESSAGE, OVERLAY_NODE, OVERLAY_NODES, OVERLAY_QUERY,
        PUB_ED25519, TON_NODE_SHARD_PUBLIC_OVERLAY_ID,
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use ton_crypto::Ed25519Keypair;

    #[test]
    fn test_exports() {
        // Verify that key types are accessible
        let _: OverlayId = OverlayId::from_bytes([0u8; 32]);
        let _cert = OverlayCertificate::empty();
        let _broadcast = OverlayBroadcast::new(vec![]);
    }

    #[test]
    fn test_overlay_id_calculation() {
        let zero_state_hash = [1u8; 32];

        // Test masterchain overlay ID
        let mc_id = OverlayId::for_masterchain(&zero_state_hash);
        let mc_id2 = calculate_overlay_id(-1, i64::MIN, &zero_state_hash);
        assert_eq!(mc_id.to_bytes(), mc_id2);

        // Test basechain overlay ID
        let bc_id = OverlayId::for_basechain(&zero_state_hash);
        assert_ne!(mc_id, bc_id);
    }

    #[test]
    fn test_certificate_flow() {
        let issuer = Ed25519Keypair::generate();
        let node = Ed25519Keypair::generate();
        let overlay_id = [1u8; 32];

        // Create certificate using public key (builder calculates ADNL short ID)
        let cert = CertificateBuilder::for_node(overlay_id, node.public_key)
            .expire_in(3600)
            .max_size(2048)
            .build(&issuer);

        // Verify certificate using public key convenience method
        assert!(cert.verify_for_node(&overlay_id, &node.public_key).is_ok());
        assert!(!cert.is_expired());
        assert!(cert.allows_size(1000));
        assert!(!cert.allows_size(3000));
    }

    #[test]
    fn test_broadcast_flow() {
        let keypair = Ed25519Keypair::generate();
        let overlay_id = [1u8; 32];

        // Create and sign broadcast
        let mut broadcast = OverlayBroadcast::new(b"test data".to_vec());
        broadcast.sign(&keypair, &overlay_id);

        // Verify
        assert!(broadcast.verify_signature(&overlay_id).is_ok());
        assert!(broadcast.validate(&overlay_id).is_ok());
    }

    #[test]
    fn test_node_flow() {
        let keypair = Ed25519Keypair::generate();
        let overlay_id = [1u8; 32];

        // Create and sign node
        let node = OverlayNode::from_keypair(&keypair, overlay_id);

        // Verify
        assert!(node.verify_signature().is_ok());
        assert!(node.is_recent(60));

        // Serialize and deserialize
        let tl_data = node.to_tl();
        let parsed = OverlayNode::from_tl(&tl_data).unwrap();
        assert_eq!(parsed.id, node.id);
        assert!(parsed.verify_signature().is_ok());
    }

    #[test]
    fn test_nodes_collection() {
        let overlay_id = [1u8; 32];
        let mut nodes = OverlayNodes::new();

        for _ in 0..5 {
            let keypair = Ed25519Keypair::generate();
            let node = OverlayNode::from_keypair(&keypair, overlay_id);
            nodes.add(node);
        }

        assert_eq!(nodes.len(), 5);

        // Serialize and deserialize
        let tl_data = nodes.to_tl();
        let parsed = OverlayNodes::from_tl(&tl_data).unwrap();
        assert_eq!(parsed.len(), 5);
    }

    #[test]
    fn test_broadcast_cache() {
        let mut cache = BroadcastCache::new(100);

        let hash1 = [1u8; 32];
        let hash2 = [2u8; 32];

        assert!(cache.mark_seen(hash1));
        assert!(!cache.mark_seen(hash1)); // Already seen

        assert!(!cache.has_seen(&hash2));
        assert!(cache.mark_seen(hash2));
        assert!(cache.has_seen(&hash2));
    }

    #[test]
    fn test_schema_ids() {
        // Verify schema IDs are accessible
        assert_eq!(schemas::OVERLAY_NODE, 0xd8f89b1c);
        assert_eq!(schemas::OVERLAY_NODES, 0x66f1e9f0);
        assert_eq!(schemas::OVERLAY_QUERY, 0x4ad47b01);
        assert_eq!(schemas::OVERLAY_BROADCAST, 0xa8b7e06c);
        assert_eq!(schemas::OVERLAY_CERTIFICATE, 0xa0d1db3e);
        assert_eq!(schemas::OVERLAY_EMPTY_CERTIFICATE, 0x8b0c0c35);
    }

    #[test]
    fn test_dht_key_for_overlay() {
        let overlay_id1 = [1u8; 32];
        let overlay_id2 = [2u8; 32];

        let key1 = dht_key_for_overlay(&overlay_id1);
        let key2 = dht_key_for_overlay(&overlay_id2);

        // Different overlay IDs should produce different DHT keys
        assert_ne!(key1, key2);

        // Same overlay ID should produce same DHT key
        let key1_again = dht_key_for_overlay(&overlay_id1);
        assert_eq!(key1, key1_again);
    }

    #[test]
    fn test_full_roundtrip() {
        let issuer = Ed25519Keypair::generate();
        let sender = Ed25519Keypair::generate();
        let overlay_id = OverlayId::for_masterchain(&[1u8; 32]);

        // Create certificate using public key (builder calculates ADNL short ID)
        let cert = CertificateBuilder::for_node(overlay_id.to_bytes(), sender.public_key)
            .expire_in(3600)
            .max_size(1024)
            .build(&issuer);

        // Create broadcast with certificate
        let mut broadcast = OverlayBroadcast::new(b"important data".to_vec())
            .with_certificate(cert);
        broadcast.sign(&sender, overlay_id.as_bytes());

        // Serialize
        let tl_data = broadcast.to_tl();

        // Deserialize
        let parsed = OverlayBroadcast::from_tl(&tl_data).unwrap();

        // Verify
        assert!(parsed.verify_signature(overlay_id.as_bytes()).is_ok());
        assert!(!parsed.certificate.is_empty());
        // Use verify_for_node which calculates ADNL short ID from public key
        assert!(parsed.certificate.verify_for_node(overlay_id.as_bytes(), &sender.public_key).is_ok());
    }
}
