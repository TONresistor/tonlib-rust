//! # ton-nft
//!
//! TEP-62 NFT (Non-Fungible Token) standard implementation for TON.
//!
//! This crate provides support for interacting with NFTs on the TON blockchain,
//! implementing the TEP-62 standard for non-fungible tokens.
//!
//! ## Overview
//!
//! The NFT standard defines two types of contracts:
//!
//! - **NFT Collection**: The main collection contract that holds collection metadata
//!   and manages NFT items. There is one NFT Collection per collection.
//!
//! - **NFT Item**: Individual NFT contracts representing owned digital assets.
//!   Each NFT item belongs to a collection and has a unique index.
//!
//! ## TEP-62 Standard
//!
//! TEP-62 defines the standard interface for non-fungible tokens on TON:
//!
//! ### Collection Get Methods
//! - **get_collection_data**: Returns collection metadata (next_item_index, content, owner)
//! - **get_nft_address_by_index**: Returns the NFT item address for a given index
//! - **get_nft_content**: Returns the full NFT content combining collection and item data
//!
//! ### Item Get Methods
//! - **get_nft_data**: Returns NFT state (init, index, collection, owner, content)
//!
//! ### Operation Codes
//!
//! - `transfer` (0x5fcc3d14): Transfer NFT ownership
//! - `ownership_assigned` (0x05138d91): Notification of ownership change
//! - `excesses` (0xd53276db): Return excess TON after operation
//! - `get_static_data` (0x2fcb26a2): Request static data (index, collection)
//! - `report_static_data` (0x8b771735): Response with static data
//!
//! ## TEP-64 Token Data Standard
//!
//! NFT metadata follows TEP-64:
//!
//! - **Off-chain (0x00)**: URI pointing to JSON metadata
//! - **On-chain (0x01)**: Dictionary with key-value pairs
//!
//! ## Example
//!
//! ```rust,no_run
//! use ton_nft::{NftCollection, NftItem, NftContent};
//! use ton_cell::MsgAddress;
//! use ton_adnl::LiteClient;
//!
//! async fn example() -> Result<(), Box<dyn std::error::Error>> {
//!     // Connect to liteserver
//!     let client = LiteClient::connect("1.2.3.4", 12345, &[0u8; 32]).await?;
//!
//!     // Create NFT Collection instance
//!     let collection_addr = MsgAddress::from_string("0:abc...").unwrap();
//!     let collection = NftCollection::new(collection_addr);
//!
//!     // Get collection information
//!     let data = collection.get_collection_data(&client).await?;
//!     println!("Total items: {}", data.next_item_index);
//!
//!     // Get NFT item address by index
//!     let nft_addr = collection.get_nft_address_by_index(&client, 0).await?;
//!
//!     // Query NFT item data
//!     let item = NftItem::from_address(nft_addr);
//!     let nft_data = item.get_nft_data(&client).await?;
//!     println!("Owner: {}", nft_data.owner);
//!     println!("Initialized: {}", nft_data.init);
//!
//!     Ok(())
//! }
//! ```
//!
//! ## Creating Transfer Messages
//!
//! ```rust
//! use ton_nft::NftItem;
//! use ton_cell::MsgAddress;
//!
//! // Create a transfer message body
//! let new_owner = MsgAddress::Internal {
//!     workchain: 0,
//!     address: [0x12; 32],
//! };
//! let response_dest = MsgAddress::Internal {
//!     workchain: 0,
//!     address: [0x34; 32],
//! };
//!
//! let body = NftItem::create_transfer_body(
//!     rand::random(),              // query_id
//!     &new_owner,                  // new owner
//!     &response_dest,              // where to send excess TON
//!     None,                        // custom payload
//!     50_000_000,                  // forward TON amount (0.05 TON)
//!     None,                        // forward payload
//! ).unwrap();
//! ```
//!
//! ## References
//!
//! - [TEP-62: NFT Standard](https://github.com/ton-blockchain/TEPs/blob/master/text/0062-nft-standard.md)
//! - [TEP-64: Token Data Standard](https://github.com/ton-blockchain/TEPs/blob/master/text/0064-token-data-standard.md)

pub mod collection;
pub mod content;
pub mod error;
pub mod item;
pub mod types;

// Re-export main types
pub use collection::{build_address_cell, parse_address_from_slice, NftCollection};
pub use content::{NftAttribute, NftContent, OnChainContent};
pub use error::{NftError, NftResult};
pub use item::{build_comment_cell, NftItem};
pub use types::{CollectionData, NftCollectionAddress, NftItemAddress, NftItemData};

// Re-export operation codes
pub use item::opcodes::{
    OP_EXCESSES, OP_GET_STATIC_DATA, OP_OWNERSHIP_ASSIGNED, OP_REPORT_STATIC_DATA, OP_TRANSFER,
};

/// High-level helper to create an NFT transfer message body.
///
/// This function creates an NFT transfer message body.
///
/// # Arguments
///
/// * `new_owner` - New owner's address
/// * `response_destination` - Address for excess TON return
/// * `forward_ton` - Amount of TON to forward with the ownership notification
/// * `comment` - Optional text comment for the transfer
///
/// # Returns
///
/// The transfer message body as a Cell.
///
/// # Example
///
/// ```rust
/// use ton_nft::transfer_nft_body;
/// use ton_cell::MsgAddress;
///
/// let new_owner = MsgAddress::Internal {
///     workchain: 0,
///     address: [0x12; 32],
/// };
/// let response_dest = MsgAddress::Internal {
///     workchain: 0,
///     address: [0x34; 32],
/// };
///
/// let body = transfer_nft_body(
///     &new_owner,
///     &response_dest,
///     50_000_000,         // 0.05 TON forward
///     Some("NFT Transfer"),
/// ).unwrap();
/// ```
pub fn transfer_nft_body(
    new_owner: &ton_cell::MsgAddress,
    response_destination: &ton_cell::MsgAddress,
    forward_ton: u128,
    comment: Option<&str>,
) -> NftResult<ton_cell::Cell> {
    let forward_payload = if let Some(c) = comment {
        Some(build_comment_cell(c)?)
    } else {
        None
    };

    NftItem::create_transfer_body(
        rand::random(), // query_id
        new_owner,
        response_destination,
        None, // custom_payload
        forward_ton,
        forward_payload,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use ton_cell::{CellSlice, MsgAddress};

    #[test]
    fn test_transfer_nft_body() {
        let new_owner = MsgAddress::Internal {
            workchain: 0,
            address: [0x12; 32],
        };
        let response = MsgAddress::Internal {
            workchain: 0,
            address: [0x34; 32],
        };

        let body = transfer_nft_body(&new_owner, &response, 50_000_000, Some("Test")).unwrap();

        // Verify opcode
        let mut slice = CellSlice::new(&body);
        let opcode = slice.load_u32().unwrap();
        assert_eq!(opcode, OP_TRANSFER);
    }

    #[test]
    fn test_transfer_nft_body_no_comment() {
        let new_owner = MsgAddress::Internal {
            workchain: 0,
            address: [0x56; 32],
        };
        let response = MsgAddress::Internal {
            workchain: 0,
            address: [0x78; 32],
        };

        let body = transfer_nft_body(&new_owner, &response, 0, None).unwrap();

        let mut slice = CellSlice::new(&body);
        let opcode = slice.load_u32().unwrap();
        assert_eq!(opcode, OP_TRANSFER);
    }

    #[test]
    fn test_opcodes_exported() {
        // Verify all opcodes are properly exported
        assert_eq!(OP_TRANSFER, 0x5fcc3d14);
        assert_eq!(OP_OWNERSHIP_ASSIGNED, 0x05138d91);
        assert_eq!(OP_EXCESSES, 0xd53276db);
        assert_eq!(OP_GET_STATIC_DATA, 0x2fcb26a2);
        assert_eq!(OP_REPORT_STATIC_DATA, 0x8b771735);
    }

    #[test]
    fn test_types_reexported() {
        // Verify main types are accessible
        let _: NftCollectionAddress;
        let _: NftItemAddress;
    }
}
