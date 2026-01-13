//! ADNL UDP protocol implementation.
//!
//! This module provides UDP-based ADNL communication for P2P node networking.
//! Unlike the TCP implementation which is used for client-server connections
//! (e.g., to liteservers), UDP ADNL is used for peer-to-peer communication
//! between TON nodes.
//!
//! ## Key Differences from TCP ADNL
//!
//! - **Connectionless**: UDP is inherently connectionless, so we manage peer state
//! - **Channels**: Encrypted channels are established between peers for efficiency
//! - **Multiple peers**: A single `AdnlNode` can communicate with many peers
//! - **Message-based**: Each datagram is a complete message (with fragmentation support)
//!
//! ## Protocol Overview
//!
//! 1. **Initial Communication**: First packet uses ECDH with peer's public key
//! 2. **Channel Creation**: Peers exchange `createChannel`/`confirmChannel` messages
//! 3. **Channel Communication**: Subsequent packets use symmetric channel keys
//!
//! ## Example
//!
//! ```rust,no_run
//! use std::net::SocketAddr;
//! use ton_adnl::udp::{AdnlNode, AdnlMessage};
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

mod channel;
mod node;
mod packet;
mod peer;

pub use channel::{AdnlChannel, ChannelState};
pub use node::AdnlNode;
pub use packet::{
    AdnlPacketContents, AdnlPacketFlags, UdpPacket,
    encode_udp_packet, decode_udp_packet,
};
pub use peer::{AdnlPeer, PeerState};

/// ADNL UDP message types.
#[derive(Debug, Clone)]
pub enum AdnlMessage {
    /// Create a new encrypted channel.
    CreateChannel {
        /// The sender's channel public key.
        key: [u8; 32],
        /// Unix timestamp.
        date: i32,
    },
    /// Confirm channel creation.
    ConfirmChannel {
        /// The confirmer's channel public key.
        key: [u8; 32],
        /// The initiator's channel public key.
        peer_key: [u8; 32],
        /// Unix timestamp.
        date: i32,
    },
    /// A query expecting a response.
    Query {
        /// Query identifier.
        query_id: [u8; 32],
        /// Query data.
        query: Vec<u8>,
    },
    /// A response to a query.
    Answer {
        /// Query identifier this answers.
        query_id: [u8; 32],
        /// Answer data.
        answer: Vec<u8>,
    },
    /// A custom message not expecting a response.
    Custom {
        /// Custom message data.
        data: Vec<u8>,
    },
    /// Part of a large message (for fragmentation).
    Part {
        /// Hash of the complete message.
        hash: [u8; 32],
        /// Total size of the complete message.
        total_size: i32,
        /// Offset of this part.
        offset: i32,
        /// Data of this part.
        data: Vec<u8>,
    },
}

impl AdnlMessage {
    /// Returns the TL schema ID for this message type.
    pub fn schema_id(&self) -> u32 {
        use crate::tl::*;
        match self {
            AdnlMessage::CreateChannel { .. } => ADNL_CREATE_CHANNEL,
            AdnlMessage::ConfirmChannel { .. } => ADNL_CONFIRM_CHANNEL,
            AdnlMessage::Query { .. } => ADNL_MESSAGE_QUERY,
            AdnlMessage::Answer { .. } => ADNL_MESSAGE_ANSWER,
            AdnlMessage::Custom { .. } => ADNL_MESSAGE_CUSTOM,
            AdnlMessage::Part { .. } => ADNL_MESSAGE_PART,
        }
    }
}
