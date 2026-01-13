//! Core NFT types.
//!
//! This module defines the fundamental types for TEP-62 NFT standard.

use ton_cell::MsgAddress;

use crate::content::NftContent;

/// NFT Collection contract address.
///
/// Wraps a MsgAddress to provide type safety for NFT Collection addresses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NftCollectionAddress(pub MsgAddress);

impl NftCollectionAddress {
    /// Creates a new NftCollectionAddress.
    pub fn new(address: MsgAddress) -> Self {
        Self(address)
    }

    /// Returns the inner address.
    pub fn address(&self) -> &MsgAddress {
        &self.0
    }

    /// Consumes self and returns the inner address.
    pub fn into_inner(self) -> MsgAddress {
        self.0
    }
}

impl From<MsgAddress> for NftCollectionAddress {
    fn from(addr: MsgAddress) -> Self {
        Self(addr)
    }
}

impl std::fmt::Display for NftCollectionAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// NFT Item contract address.
///
/// Wraps a MsgAddress to provide type safety for NFT Item addresses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NftItemAddress(pub MsgAddress);

impl NftItemAddress {
    /// Creates a new NftItemAddress.
    pub fn new(address: MsgAddress) -> Self {
        Self(address)
    }

    /// Returns the inner address.
    pub fn address(&self) -> &MsgAddress {
        &self.0
    }

    /// Consumes self and returns the inner address.
    pub fn into_inner(self) -> MsgAddress {
        self.0
    }
}

impl From<MsgAddress> for NftItemAddress {
    fn from(addr: MsgAddress) -> Self {
        Self(addr)
    }
}

impl std::fmt::Display for NftItemAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Data returned by the `get_collection_data` get method on NFT Collection contract.
///
/// Contains all the information about an NFT collection.
#[derive(Debug, Clone)]
pub struct CollectionData {
    /// Index of the next item to be minted.
    pub next_item_index: u64,
    /// Collection metadata (TEP-64 content).
    pub content: NftContent,
    /// Address of the collection owner.
    pub owner: MsgAddress,
}

impl CollectionData {
    /// Creates a new CollectionData.
    pub fn new(next_item_index: u64, content: NftContent, owner: MsgAddress) -> Self {
        Self {
            next_item_index,
            content,
            owner,
        }
    }
}

/// Data returned by the `get_nft_data` get method on NFT Item contract.
///
/// Contains the state of an individual NFT item.
#[derive(Debug, Clone)]
pub struct NftItemData {
    /// Whether the NFT is initialized.
    pub init: bool,
    /// Index of this NFT in the collection.
    pub index: u64,
    /// Address of the NFT Collection contract.
    pub collection: MsgAddress,
    /// Address of the NFT owner.
    pub owner: MsgAddress,
    /// Individual NFT content (combined with collection content for full metadata).
    pub content: NftContent,
}

impl NftItemData {
    /// Creates a new NftItemData.
    pub fn new(
        init: bool,
        index: u64,
        collection: MsgAddress,
        owner: MsgAddress,
        content: NftContent,
    ) -> Self {
        Self {
            init,
            index,
            collection,
            owner,
            content,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nft_collection_address() {
        let addr = MsgAddress::Internal {
            workchain: 0,
            address: [0xAB; 32],
        };
        let collection_addr = NftCollectionAddress::new(addr.clone());

        assert_eq!(collection_addr.address(), &addr);
        assert_eq!(collection_addr.clone().into_inner(), addr);
    }

    #[test]
    fn test_nft_item_address() {
        let addr = MsgAddress::Internal {
            workchain: 0,
            address: [0xCD; 32],
        };
        let item_addr = NftItemAddress::new(addr.clone());

        assert_eq!(item_addr.address(), &addr);
        assert_eq!(item_addr.clone().into_inner(), addr);
    }

    #[test]
    fn test_nft_collection_address_from() {
        let addr = MsgAddress::Internal {
            workchain: -1,
            address: [0x12; 32],
        };
        let collection_addr: NftCollectionAddress = addr.clone().into();

        assert_eq!(collection_addr.0, addr);
    }

    #[test]
    fn test_nft_item_address_from() {
        let addr = MsgAddress::Internal {
            workchain: 0,
            address: [0x34; 32],
        };
        let item_addr: NftItemAddress = addr.clone().into();

        assert_eq!(item_addr.0, addr);
    }
}
