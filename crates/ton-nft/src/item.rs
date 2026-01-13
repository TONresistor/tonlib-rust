//! NFT Item contract interface.
//!
//! The NFT Item contract represents an individual NFT owned by an address.
//! It provides methods to query NFT data and create transfer messages.

use std::sync::Arc;

use ton_adnl::{AccountAddress, LiteClient, RunMethodResult};
use ton_cell::{BagOfCells, Cell, CellBuilder, CellSlice, MsgAddress};

use crate::collection::parse_address_from_slice;
use crate::content::NftContent;
use crate::error::{NftError, NftResult};
use crate::types::{NftItemAddress, NftItemData};

/// TEP-62 Operation codes for NFT.
pub mod opcodes {
    /// Transfer NFT ownership (op::transfer).
    pub const OP_TRANSFER: u32 = 0x5fcc3d14;

    /// Notification of ownership change to new owner.
    pub const OP_OWNERSHIP_ASSIGNED: u32 = 0x05138d91;

    /// Return excess TON after operation.
    pub const OP_EXCESSES: u32 = 0xd53276db;

    /// Request static data (index and collection).
    pub const OP_GET_STATIC_DATA: u32 = 0x2fcb26a2;

    /// Response with static data.
    pub const OP_REPORT_STATIC_DATA: u32 = 0x8b771735;
}

pub use opcodes::*;

/// NFT Item contract interface.
///
/// Provides methods to interact with a TEP-62 NFT Item contract.
#[derive(Debug, Clone)]
pub struct NftItem {
    /// Address of the NFT Item contract.
    address: MsgAddress,
}

impl NftItem {
    /// Creates a new NftItem instance.
    pub fn new(address: MsgAddress) -> Self {
        Self { address }
    }

    /// Creates a new NftItem from an NftItemAddress.
    pub fn from_address(address: NftItemAddress) -> Self {
        Self {
            address: address.into_inner(),
        }
    }

    /// Returns the address of the NFT Item contract.
    pub fn address(&self) -> &MsgAddress {
        &self.address
    }

    /// Returns the address as an NftItemAddress.
    pub fn item_address(&self) -> NftItemAddress {
        NftItemAddress::new(self.address.clone())
    }

    /// Gets NFT data from the contract.
    ///
    /// Calls the `get_nft_data` get method which returns:
    /// - init: bool (whether NFT is initialized)
    /// - index: u64 (NFT index in collection)
    /// - collection: MsgAddress (collection contract address)
    /// - owner: MsgAddress (current owner)
    /// - content: Cell (individual item content)
    pub async fn get_nft_data(&self, client: &LiteClient) -> NftResult<NftItemData> {
        let account_addr = msg_address_to_account(&self.address)?;

        let result = client
            .run_get_method_by_name(&account_addr, "get_nft_data", &[])
            .await
            .map_err(|e| NftError::NetworkError(e.to_string()))?;

        parse_nft_data(&result)
    }

    /// Creates a transfer message body.
    ///
    /// # Arguments
    ///
    /// * `query_id` - Query ID for response tracking
    /// * `new_owner` - New owner's address
    /// * `response_destination` - Address for excess TON and ownership_assigned notification
    /// * `custom_payload` - Optional custom payload cell
    /// * `forward_amount` - Amount of TON to forward with ownership_assigned notification
    /// * `forward_payload` - Optional payload to forward with notification
    ///
    /// # Message Format (TL-B)
    ///
    /// ```text
    /// transfer#5fcc3d14
    ///   query_id:uint64
    ///   new_owner:MsgAddress
    ///   response_destination:MsgAddress
    ///   custom_payload:(Maybe ^Cell)
    ///   forward_amount:(VarUInteger 16)
    ///   forward_payload:(Either Cell ^Cell)
    /// ```
    pub fn create_transfer_body(
        query_id: u64,
        new_owner: &MsgAddress,
        response_destination: &MsgAddress,
        custom_payload: Option<Cell>,
        forward_amount: u128,
        forward_payload: Option<Cell>,
    ) -> NftResult<Cell> {
        let mut builder = CellBuilder::new();

        // op::transfer
        builder.store_u32(OP_TRANSFER)?;

        // query_id
        builder.store_u64(query_id)?;

        // new_owner
        builder.store_address(new_owner)?;

        // response_destination
        builder.store_address(response_destination)?;

        // custom_payload (Maybe ^Cell)
        if let Some(payload) = custom_payload {
            builder.store_bit(true)?;
            builder.store_ref(Arc::new(payload))?;
        } else {
            builder.store_bit(false)?;
        }

        // forward_amount (VarUInteger 16 = Coins)
        builder.store_coins(forward_amount)?;

        // forward_payload (Either Cell ^Cell)
        // We use ^Cell format (bit=1, then reference) for simplicity
        if let Some(payload) = forward_payload {
            builder.store_bit(true)?;
            builder.store_ref(Arc::new(payload))?;
        } else {
            builder.store_bit(false)?;
        }

        Ok(builder.build()?)
    }

    /// Creates a get_static_data request body.
    ///
    /// This message requests the NFT to report its index and collection address.
    ///
    /// # Arguments
    ///
    /// * `query_id` - Query ID for response tracking
    ///
    /// # Message Format (TL-B)
    ///
    /// ```text
    /// get_static_data#2fcb26a2 query_id:uint64 = InternalMsgBody;
    /// ```
    pub fn create_get_static_data_body(query_id: u64) -> NftResult<Cell> {
        let mut builder = CellBuilder::new();

        // op::get_static_data
        builder.store_u32(OP_GET_STATIC_DATA)?;

        // query_id
        builder.store_u64(query_id)?;

        Ok(builder.build()?)
    }
}

impl From<MsgAddress> for NftItem {
    fn from(address: MsgAddress) -> Self {
        Self::new(address)
    }
}

impl From<NftItemAddress> for NftItem {
    fn from(address: NftItemAddress) -> Self {
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

/// Parses the result of get_nft_data.
fn parse_nft_data(result: &RunMethodResult) -> NftResult<NftItemData> {
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

    // Parse stack: [init, index, collection, owner, content]
    let entries = parse_stack_entries(stack_cell, 5)?;

    let init = extract_int_as_bool(&entries[0])?;
    let index = extract_int_as_u64(&entries[1])?;
    let collection = extract_address(&entries[2])?;
    let owner = extract_address(&entries[3])?;
    let content = extract_content(&entries[4])?;

    Ok(NftItemData {
        init,
        index,
        collection,
        owner,
        content,
    })
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

/// Extracts an integer value as bool (-1 = true, 0 = false).
fn extract_int_as_bool(value: &StackValue) -> NftResult<bool> {
    match value {
        StackValue::Int(n) => Ok(*n != 0),
        _ => Err(NftError::InvalidStackEntry {
            expected: "integer (bool)",
            actual: format!("{:?}", value),
        }),
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

/// Creates a comment cell for use as forward_payload.
///
/// This creates a cell with a text comment that will be shown
/// in wallet applications when receiving the ownership notification.
pub fn build_comment_cell(comment: &str) -> NftResult<Cell> {
    let mut builder = CellBuilder::new();

    // Comment prefix: 0x00000000
    builder.store_u32(0)?;

    // Comment text as bytes
    builder.store_bytes(comment.as_bytes())?;

    Ok(builder.build()?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nft_item_new() {
        let addr = MsgAddress::Internal {
            workchain: 0,
            address: [0xAB; 32],
        };
        let item = NftItem::new(addr.clone());

        assert_eq!(item.address(), &addr);
    }

    #[test]
    fn test_nft_item_from_address() {
        let addr = MsgAddress::Internal {
            workchain: -1,
            address: [0xCD; 32],
        };
        let item_addr = NftItemAddress::new(addr.clone());
        let item = NftItem::from_address(item_addr);

        assert_eq!(item.address(), &addr);
    }

    #[test]
    fn test_create_transfer_body() {
        let new_owner = MsgAddress::Internal {
            workchain: 0,
            address: [0x12; 32],
        };
        let response_dest = MsgAddress::Internal {
            workchain: 0,
            address: [0x34; 32],
        };

        let body = NftItem::create_transfer_body(
            12345,        // query_id
            &new_owner,
            &response_dest,
            None,         // custom_payload
            50_000_000,   // forward_amount (0.05 TON)
            None,         // forward_payload
        )
        .unwrap();

        // Verify the cell was created
        assert!(body.bit_len() > 0);

        // Parse and verify the opcode
        let mut slice = CellSlice::new(&body);
        let opcode = slice.load_u32().unwrap();
        assert_eq!(opcode, OP_TRANSFER);

        // Verify query_id
        let query_id = slice.load_u64().unwrap();
        assert_eq!(query_id, 12345);
    }

    #[test]
    fn test_create_transfer_body_with_payload() {
        let new_owner = MsgAddress::Internal {
            workchain: 0,
            address: [0x56; 32],
        };
        let response_dest = MsgAddress::Internal {
            workchain: 0,
            address: [0x78; 32],
        };

        let comment = build_comment_cell("NFT Transfer").unwrap();

        let body = NftItem::create_transfer_body(
            0,
            &new_owner,
            &response_dest,
            None,
            100_000_000,
            Some(comment),
        )
        .unwrap();

        // Verify the cell has a reference (for forward_payload)
        assert!(body.reference_count() > 0);
    }

    #[test]
    fn test_create_get_static_data_body() {
        let body = NftItem::create_get_static_data_body(99999).unwrap();

        // Parse and verify
        let mut slice = CellSlice::new(&body);
        let opcode = slice.load_u32().unwrap();
        assert_eq!(opcode, OP_GET_STATIC_DATA);

        let query_id = slice.load_u64().unwrap();
        assert_eq!(query_id, 99999);
    }

    #[test]
    fn test_build_comment_cell() {
        let comment = "Transfer NFT";
        let cell = build_comment_cell(comment).unwrap();

        let mut slice = CellSlice::new(&cell);

        // Verify comment prefix
        let prefix = slice.load_u32().unwrap();
        assert_eq!(prefix, 0);

        // Verify comment text
        let bytes = slice.load_bytes(comment.len()).unwrap();
        let text = String::from_utf8(bytes).unwrap();
        assert_eq!(text, comment);
    }

    #[test]
    fn test_opcodes() {
        assert_eq!(OP_TRANSFER, 0x5fcc3d14);
        assert_eq!(OP_OWNERSHIP_ASSIGNED, 0x05138d91);
        assert_eq!(OP_EXCESSES, 0xd53276db);
        assert_eq!(OP_GET_STATIC_DATA, 0x2fcb26a2);
        assert_eq!(OP_REPORT_STATIC_DATA, 0x8b771735);
    }

    #[test]
    fn test_from_trait_implementations() {
        let addr = MsgAddress::Internal {
            workchain: 0,
            address: [0xDE; 32],
        };

        // From MsgAddress
        let item1: NftItem = addr.clone().into();
        assert_eq!(item1.address(), &addr);

        // From NftItemAddress
        let item_addr = NftItemAddress::new(addr.clone());
        let item2: NftItem = item_addr.into();
        assert_eq!(item2.address(), &addr);
    }
}
