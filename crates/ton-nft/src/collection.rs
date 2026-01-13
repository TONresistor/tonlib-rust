//! NFT Collection contract interface.
//!
//! The NFT Collection contract holds collection metadata and manages NFT items.
//! It provides methods to query collection information and find NFT item addresses.

use std::sync::Arc;

use ton_adnl::{AccountAddress, LiteClient, RunMethodResult};
use ton_cell::{BagOfCells, Cell, CellBuilder, CellSlice, MsgAddress};

use crate::content::NftContent;
use crate::error::{NftError, NftResult};
use crate::types::{CollectionData, NftCollectionAddress, NftItemAddress};

/// NFT Collection contract interface.
///
/// Provides methods to interact with a TEP-62 NFT Collection contract.
#[derive(Debug, Clone)]
pub struct NftCollection {
    /// Address of the NFT Collection contract.
    address: MsgAddress,
}

impl NftCollection {
    /// Creates a new NftCollection instance.
    pub fn new(address: MsgAddress) -> Self {
        Self { address }
    }

    /// Creates a new NftCollection from an NftCollectionAddress.
    pub fn from_address(address: NftCollectionAddress) -> Self {
        Self {
            address: address.into_inner(),
        }
    }

    /// Returns the address of the NFT Collection contract.
    pub fn address(&self) -> &MsgAddress {
        &self.address
    }

    /// Returns the address as an NftCollectionAddress.
    pub fn collection_address(&self) -> NftCollectionAddress {
        NftCollectionAddress::new(self.address.clone())
    }

    /// Gets collection data from the contract.
    ///
    /// Calls the `get_collection_data` get method which returns:
    /// - next_item_index: u64
    /// - content: Cell (TEP-64 content)
    /// - owner: MsgAddress
    pub async fn get_collection_data(&self, client: &LiteClient) -> NftResult<CollectionData> {
        let account_addr = msg_address_to_account(&self.address)?;

        let result = client
            .run_get_method_by_name(&account_addr, "get_collection_data", &[])
            .await
            .map_err(|e| NftError::NetworkError(e.to_string()))?;

        parse_collection_data(&result)
    }

    /// Gets the NFT item address for a specific index.
    ///
    /// Calls the `get_nft_address_by_index` get method with the item index.
    pub async fn get_nft_address_by_index(
        &self,
        client: &LiteClient,
        index: u64,
    ) -> NftResult<NftItemAddress> {
        let account_addr = msg_address_to_account(&self.address)?;

        // Build the index as a parameter
        let index_cell = build_index_cell(index)?;
        let params = BagOfCells::from_root(index_cell).serialize()?;

        let result = client
            .run_get_method(
                &result_block_id(client).await?,
                &account_addr,
                compute_method_id("get_nft_address_by_index"),
                &params,
                4,
            )
            .await
            .map_err(|e| NftError::NetworkError(e.to_string()))?;

        parse_nft_address(&result)
    }

    /// Gets the full NFT content for a specific index.
    ///
    /// Calls the `get_nft_content` get method with the index and individual item content.
    /// This combines collection content with item content according to TEP-64.
    pub async fn get_nft_content(
        &self,
        client: &LiteClient,
        index: u64,
        item_content: &Cell,
    ) -> NftResult<NftContent> {
        let account_addr = msg_address_to_account(&self.address)?;

        // Build parameters: index and item_content cell
        let mut builder = CellBuilder::new();
        builder.store_u64(index)?;
        builder.store_ref(Arc::new(item_content.clone()))?;
        let params_cell = builder.build()?;
        let params = BagOfCells::from_root(params_cell).serialize()?;

        let result = client
            .run_get_method(
                &result_block_id(client).await?,
                &account_addr,
                compute_method_id("get_nft_content"),
                &params,
                4,
            )
            .await
            .map_err(|e| NftError::NetworkError(e.to_string()))?;

        parse_nft_content(&result)
    }
}

impl From<MsgAddress> for NftCollection {
    fn from(address: MsgAddress) -> Self {
        Self::new(address)
    }
}

impl From<NftCollectionAddress> for NftCollection {
    fn from(address: NftCollectionAddress) -> Self {
        Self::from_address(address)
    }
}

/// Converts a MsgAddress to AccountAddress.
fn msg_address_to_account(addr: &MsgAddress) -> NftResult<AccountAddress> {
    match addr {
        MsgAddress::Internal { workchain, address } => {
            Ok(AccountAddress::new(*workchain, *address))
        }
        _ => Err(NftError::InvalidAddress(
            "Only internal addresses are supported".to_string(),
        )),
    }
}

/// Builds an address cell for use as a get method parameter.
pub fn build_address_cell(addr: &MsgAddress) -> NftResult<Cell> {
    let mut builder = CellBuilder::new();
    builder.store_address(addr)?;
    Ok(builder.build()?)
}

/// Builds an index cell for use as a get method parameter.
fn build_index_cell(index: u64) -> NftResult<Cell> {
    let mut builder = CellBuilder::new();
    builder.store_u64(index)?;
    Ok(builder.build()?)
}

/// Parses an address from a cell/slice.
pub fn parse_address_from_slice(cell: &Cell) -> NftResult<MsgAddress> {
    let mut slice = CellSlice::new(cell);
    Ok(slice.load_address()?)
}

/// Gets the latest block ID for running get methods.
async fn result_block_id(client: &LiteClient) -> NftResult<ton_adnl::BlockIdExt> {
    let mc_info = client
        .get_masterchain_info()
        .await
        .map_err(|e| NftError::NetworkError(e.to_string()))?;
    Ok(mc_info.last)
}

/// Computes a get method ID from its name.
fn compute_method_id(name: &str) -> u64 {
    ton_adnl::compute_method_id(name)
}

/// Parses the result of get_collection_data.
fn parse_collection_data(result: &RunMethodResult) -> NftResult<CollectionData> {
    if result.exit_code != 0 {
        return Err(NftError::GetMethodFailed(result.exit_code));
    }

    let result_data = result
        .result
        .as_ref()
        .ok_or_else(|| NftError::UnexpectedResult("No result data".to_string()))?;

    let boc = BagOfCells::deserialize(result_data)?;
    let stack_cell = boc
        .single_root()
        .map_err(|_| NftError::UnexpectedResult("Invalid stack BoC".to_string()))?;

    // Parse stack: [next_item_index, content, owner]
    let entries = parse_stack_entries(stack_cell, 3)?;

    let next_item_index = extract_int_as_u64(&entries[0])?;
    let content = extract_content(&entries[1])?;
    let owner = extract_address(&entries[2])?;

    Ok(CollectionData {
        next_item_index,
        content,
        owner,
    })
}

/// Parses the result of get_nft_address_by_index.
fn parse_nft_address(result: &RunMethodResult) -> NftResult<NftItemAddress> {
    if result.exit_code != 0 {
        return Err(NftError::GetMethodFailed(result.exit_code));
    }

    let result_data = result
        .result
        .as_ref()
        .ok_or_else(|| NftError::UnexpectedResult("No result data".to_string()))?;

    let boc = BagOfCells::deserialize(result_data)?;
    let stack_cell = boc
        .single_root()
        .map_err(|_| NftError::UnexpectedResult("Invalid stack BoC".to_string()))?;

    let entries = parse_stack_entries(stack_cell, 1)?;
    let address = extract_address(&entries[0])?;

    Ok(NftItemAddress::new(address))
}

/// Parses the result of get_nft_content.
fn parse_nft_content(result: &RunMethodResult) -> NftResult<NftContent> {
    if result.exit_code != 0 {
        return Err(NftError::GetMethodFailed(result.exit_code));
    }

    let result_data = result
        .result
        .as_ref()
        .ok_or_else(|| NftError::UnexpectedResult("No result data".to_string()))?;

    let boc = BagOfCells::deserialize(result_data)?;
    let stack_cell = boc
        .single_root()
        .map_err(|_| NftError::UnexpectedResult("Invalid stack BoC".to_string()))?;

    let entries = parse_stack_entries(stack_cell, 1)?;
    extract_content(&entries[0])
}

/// Stack entry representation for parsing.
#[derive(Debug)]
enum StackValue {
    Int(i128),
    Cell(Arc<Cell>),
    Slice(Arc<Cell>),
}

/// Parses stack entries from a stack cell.
fn parse_stack_entries(stack_cell: &Cell, expected: usize) -> NftResult<Vec<StackValue>> {
    let mut entries = Vec::with_capacity(expected);
    let mut slice = CellSlice::new(stack_cell);

    // Skip depth field
    let _ = slice.load_uint(24);

    // Parse elements from references
    for i in 0..expected.min(stack_cell.reference_count()) {
        if let Some(entry_cell) = stack_cell.reference(i) {
            let entry = parse_stack_entry(entry_cell)?;
            entries.push(entry);
        }
    }

    if entries.len() < expected {
        return Err(NftError::StackUnderflow {
            expected,
            actual: entries.len(),
        });
    }

    Ok(entries)
}

/// Parses a single stack entry from a cell.
fn parse_stack_entry(cell: &Cell) -> NftResult<StackValue> {
    let mut slice = CellSlice::new(cell);

    if slice.bits_left() < 8 {
        return Err(NftError::UnexpectedResult("Empty stack entry".to_string()));
    }

    let entry_type = slice.load_u8()?;

    match entry_type {
        0 => Ok(StackValue::Int(0)),
        1 => {
            let value = slice.load_i64()? as i128;
            Ok(StackValue::Int(value))
        }
        2 => {
            if slice.bits_left() >= 64 {
                let value = slice.load_i64()? as i128;
                Ok(StackValue::Int(value))
            } else {
                Ok(StackValue::Int(0))
            }
        }
        3 | 5 => {
            if slice.refs_left() > 0 {
                let ref_cell = slice.load_ref()?;
                Ok(StackValue::Cell(Arc::new(ref_cell.clone())))
            } else {
                Err(NftError::UnexpectedResult(
                    "Cell entry without reference".to_string(),
                ))
            }
        }
        4 => {
            if slice.refs_left() > 0 {
                let ref_cell = slice.load_ref()?;
                Ok(StackValue::Slice(Arc::new(ref_cell.clone())))
            } else {
                Err(NftError::UnexpectedResult(
                    "Slice entry without reference".to_string(),
                ))
            }
        }
        _ => {
            if cell.reference_count() > 0
                && let Some(ref_cell) = cell.reference(0) {
                    return Ok(StackValue::Cell(ref_cell.clone()));
                }
            Err(NftError::UnexpectedResult(format!(
                "Unknown stack entry type: {}",
                entry_type
            )))
        }
    }
}

/// Extracts an integer value as u64.
fn extract_int_as_u64(value: &StackValue) -> NftResult<u64> {
    match value {
        StackValue::Int(n) => {
            if *n >= 0 && *n <= u64::MAX as i128 {
                Ok(*n as u64)
            } else {
                Err(NftError::UnexpectedResult(format!(
                    "Value out of range for u64: {}",
                    n
                )))
            }
        }
        _ => Err(NftError::InvalidStackEntry {
            expected: "integer",
            actual: format!("{:?}", value),
        }),
    }
}

/// Extracts an address from a slice or cell value.
fn extract_address(value: &StackValue) -> NftResult<MsgAddress> {
    match value {
        StackValue::Slice(cell) | StackValue::Cell(cell) => parse_address_from_slice(cell),
        StackValue::Int(_) => Ok(MsgAddress::Null),
    }
}

/// Extracts NftContent from a cell value.
fn extract_content(value: &StackValue) -> NftResult<NftContent> {
    match value {
        StackValue::Cell(cell) => NftContent::from_cell(cell),
        _ => Err(NftError::InvalidStackEntry {
            expected: "cell",
            actual: format!("{:?}", value),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nft_collection_new() {
        let addr = MsgAddress::Internal {
            workchain: 0,
            address: [0xAB; 32],
        };
        let collection = NftCollection::new(addr.clone());

        assert_eq!(collection.address(), &addr);
    }

    #[test]
    fn test_nft_collection_from_address() {
        let addr = MsgAddress::Internal {
            workchain: -1,
            address: [0xCD; 32],
        };
        let collection_addr = NftCollectionAddress::new(addr.clone());
        let collection = NftCollection::from_address(collection_addr);

        assert_eq!(collection.address(), &addr);
    }

    #[test]
    fn test_collection_address() {
        let addr = MsgAddress::Internal {
            workchain: 0,
            address: [0x12; 32],
        };
        let collection = NftCollection::new(addr.clone());

        let collection_addr = collection.collection_address();
        assert_eq!(collection_addr.address(), &addr);
    }

    #[test]
    fn test_msg_address_to_account() {
        let addr = MsgAddress::Internal {
            workchain: 0,
            address: [0x34; 32],
        };

        let account = msg_address_to_account(&addr).unwrap();
        assert_eq!(account.workchain, 0);
        assert_eq!(account.address, [0x34; 32]);
    }

    #[test]
    fn test_msg_address_to_account_null() {
        let addr = MsgAddress::Null;
        let result = msg_address_to_account(&addr);
        assert!(result.is_err());
    }

    #[test]
    fn test_build_address_cell() {
        let addr = MsgAddress::Internal {
            workchain: 0,
            address: [0x56; 32],
        };

        let cell = build_address_cell(&addr).unwrap();

        // Verify we can parse it back
        let parsed = parse_address_from_slice(&cell).unwrap();
        assert_eq!(parsed, addr);
    }

    #[test]
    fn test_build_index_cell() {
        let index = 12345u64;
        let cell = build_index_cell(index).unwrap();

        let mut slice = CellSlice::new(&cell);
        let parsed = slice.load_u64().unwrap();
        assert_eq!(parsed, index);
    }

    #[test]
    fn test_from_trait_implementations() {
        let addr = MsgAddress::Internal {
            workchain: 0,
            address: [0x78; 32],
        };

        // From MsgAddress
        let collection1: NftCollection = addr.clone().into();
        assert_eq!(collection1.address(), &addr);

        // From NftCollectionAddress
        let collection_addr = NftCollectionAddress::new(addr.clone());
        let collection2: NftCollection = collection_addr.into();
        assert_eq!(collection2.address(), &addr);
    }
}
