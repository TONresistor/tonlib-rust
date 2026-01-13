//! # ton-adnl
//!
//! ADNL (Abstract Datagram Network Layer) protocol implementation for TON.
//!
//! This crate provides the networking layer for communicating with TON nodes:
//!
//! - **TCP ADNL**: Client-server communication with liteservers
//! - **UDP ADNL**: Peer-to-peer communication between nodes
//!
//! ## TCP ADNL (Client-Server)
//!
//! Used for connecting to liteservers. Features:
//!
//! - **Handshake**: Establishes an encrypted channel using ECDH and AES-CTR
//! - **Packet encoding**: Encodes/decodes ADNL packets with checksums
//! - **Query wrapping**: Wraps queries in the required TL structures
//! - **Connection management**: Async TCP client with ping/pong keepalive
//!
//! ### TCP Protocol Overview
//!
//! 1. Client generates 160 random bytes and derives cipher keys
//! 2. Client calculates ECDH shared secret with server's public key
//! 3. Client sends handshake packet (server key ID, client pubkey, encrypted params)
//! 4. Server responds with empty ADNL packet to confirm
//! 5. All subsequent communication is encrypted with AES-CTR
//!
//! ### TCP Example
//!
//! ```rust,no_run
//! use std::net::SocketAddr;
//! use ton_adnl::AdnlClient;
//!
//! async fn connect_to_liteserver() -> Result<(), Box<dyn std::error::Error>> {
//!     // Liteserver address and public key (from global config)
//!     let addr: SocketAddr = "1.2.3.4:12345".parse()?;
//!     let server_pubkey = [0u8; 32]; // Replace with actual server pubkey
//!
//!     // Connect and perform handshake
//!     let mut client = AdnlClient::connect(addr, &server_pubkey).await?;
//!
//!     // Send a ping to test the connection
//!     client.ping().await?;
//!
//!     // Query masterchain info (using schema ID)
//!     let query = 0x2ee6b589u32.to_le_bytes(); // liteServer.getMasterchainInfo
//!     let response = client.query(&query).await?;
//!
//!     println!("Response: {} bytes", response.len());
//!
//!     // Gracefully close
//!     client.shutdown().await?;
//!
//!     Ok(())
//! }
//! ```
//!
//! ## UDP ADNL (Peer-to-Peer)
//!
//! Used for P2P communication between TON nodes. Features:
//!
//! - **Channel establishment**: Secure channels using ECDH key exchange
//! - **Multiple peers**: Single node can communicate with many peers
//! - **Message fragmentation**: Support for large messages split across packets
//! - **Sequence numbers**: Reliable message ordering
//!
//! ### UDP Protocol Overview
//!
//! 1. Initial packets use ECDH encryption with peer's public key
//! 2. Peers exchange createChannel/confirmChannel messages
//! 3. Channel established with symmetric encryption keys
//! 4. Subsequent packets use efficient channel encryption
//!
//! ### UDP Example
//!
//! ```rust,no_run
//! use std::net::SocketAddr;
//! use ton_adnl::udp::AdnlNode;
//!
//! async fn run_node() -> Result<(), Box<dyn std::error::Error>> {
//!     // Create a node bound to a local address
//!     let mut node = AdnlNode::bind("0.0.0.0:30303".parse()?).await?;
//!
//!     // Add a peer
//!     let peer_addr: SocketAddr = "1.2.3.4:30303".parse()?;
//!     let peer_pubkey = [0u8; 32]; // Replace with actual peer pubkey
//!     node.add_peer(peer_addr, &peer_pubkey).await?;
//!
//!     // Send a query
//!     let peer_id = node.get_peer_id(&peer_pubkey);
//!     let response = node.send_query(&peer_id, b"Hello").await?;
//!
//!     Ok(())
//! }
//! ```
//!
//! ## Packet Formats
//!
//! ### TCP Packet Format
//!
//! ```text
//! +----------+----------+----------------------+-------------+
//! |  Size    |  Nonce   |      Payload         |  Checksum   |
//! | 4 bytes  | 32 bytes |    N-64 bytes        |  32 bytes   |
//! | (LE u32) | (random) |                      |  (SHA256)   |
//! +----------+----------+----------------------+-------------+
//! ```
//!
//! ### UDP Initial Packet Format
//!
//! ```text
//! +----------------+------------------+------------------+------------------+
//! | Recipient ID   | Sender Pubkey    | SHA256(content)  | Encrypted Content|
//! | 32 bytes       | 32 bytes         | 32 bytes         | Variable         |
//! +----------------+------------------+------------------+------------------+
//! ```
//!
//! ### UDP Channel Packet Format
//!
//! ```text
//! +----------------+------------------+------------------+
//! | Channel ID     | SHA256(content)  | Encrypted Content|
//! | 32 bytes       | 32 bytes         | Variable         |
//! +----------------+------------------+------------------+
//! ```
//!
//! The content in all packets is encrypted with AES-256-CTR.

mod address;
mod client;
mod error;
mod handshake;
mod packet;
mod tl;
pub mod udp;

// Lite Client modules
pub mod lite_client;
pub mod lite_tl;
pub mod lite_types;

// Re-export main types
pub use address::{AdnlAddress, compute_key_id};
pub use client::{AdnlClient, DEFAULT_PING_INTERVAL};
pub use error::{AdnlError, Result};
pub use handshake::{
    build_handshake_packet, encrypt_handshake_params, perform_handshake,
    HandshakeParams, SessionCiphers, HANDSHAKE_PACKET_SIZE, HANDSHAKE_PARAMS_SIZE,
};
pub use packet::{
    create_ping, create_ping_with_id, decode_packet, encode_packet, encode_packet_with_nonce,
    encrypt_packet, decrypt_packet, generate_query_id, parse_pong, unwrap_liteserver_response,
    wrap_liteserver_query, CHECKSUM_SIZE, MAX_PACKET_SIZE, MIN_PACKET_SIZE, NONCE_SIZE,
    PACKET_OVERHEAD,
};

// Re-export TL schema IDs for convenience
pub mod schemas {
    //! TL schema IDs for ADNL protocol messages.
    pub use crate::tl::{
        ADNL_MESSAGE_ANSWER, ADNL_MESSAGE_CUSTOM, ADNL_MESSAGE_QUERY,
        LITESERVER_GET_MASTERCHAIN_INFO, LITESERVER_GET_TIME, LITESERVER_QUERY,
        PUB_ED25519, TCP_PING, TCP_PONG,
        // UDP ADNL schema IDs
        ADNL_CREATE_CHANNEL, ADNL_CONFIRM_CHANNEL, ADNL_MESSAGE_PART, ADNL_PACKET_CONTENTS,
    };
}

// Re-export TL utilities
pub use tl::{TlReader, TlWriter, encode_bytes, decode_bytes};

// Re-export LiteClient types for convenience
pub use lite_client::LiteClient;
pub use lite_types::{
    AccountAddress, AccountState, AllShardsInfo, BlockData, BlockHeader, BlockId, BlockIdExt,
    ConfigInfo, LiteServerError, LiteServerVersion, MasterchainInfo, MasterchainInfoExt,
    RunMethodResult, SendMsgStatus, ShardInfo, StackEntry, TransactionId, TransactionId3,
    TransactionInfo, TransactionList, ZeroStateIdExt, compute_method_id,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exports() {
        // Verify that key types are accessible
        let _ = AdnlAddress::from_bytes([0u8; 32]);
        let _ = generate_query_id();
        let _ = create_ping();
    }

    #[test]
    fn test_constants() {
        assert_eq!(HANDSHAKE_PACKET_SIZE, 256);
        assert_eq!(HANDSHAKE_PARAMS_SIZE, 160);
        assert_eq!(NONCE_SIZE, 32);
        assert_eq!(CHECKSUM_SIZE, 32);
        assert_eq!(PACKET_OVERHEAD, 64);
    }

    #[test]
    fn test_schema_ids() {
        assert_eq!(schemas::TCP_PING, 0x9a2b084d);
        assert_eq!(schemas::TCP_PONG, 0x4f15c5d8);
        assert_eq!(schemas::ADNL_MESSAGE_QUERY, 0x7af98bb4);
        assert_eq!(schemas::ADNL_MESSAGE_ANSWER, 0x1684ac0f);
        assert_eq!(schemas::LITESERVER_QUERY, 0xdf068c79);
    }
}
