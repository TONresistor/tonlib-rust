//! Jetton Master contract interface.
//!
//! The Jetton Master contract holds token metadata and manages the token supply.
//! It provides methods to query token information and find wallet addresses.

use std::sync::Arc;

use ton_adnl::{AccountAddress, LiteClient, RunMethodResult};
use ton_cell::{BagOfCells, Cell, CellSlice, MsgAddress, CellBuilder};

use crate::error::{JettonError, JettonResult};
use crate::metadata::JettonContent;
use crate::types::{JettonData, JettonMasterAddress, JettonWalletAddress};

/// Jetton Master contract interface.
///
/// Provides methods to interact with a TEP-74 Jetton Master contract.
#[derive(Debug, Clone)]
pub struct JettonMaster {
    /// Address of the Jetton Master contract.
    address: MsgAddress,
}

impl JettonMaster {
    /// Creates a new JettonMaster instance.
    pub fn new(address: MsgAddress) -> Self {
        Self { address }
    }

    /// Creates a new JettonMaster from a JettonMasterAddress.
    pub fn from_address(address: JettonMasterAddress) -> Self {
        Self {
            address: address.into_inner(),
        }
    }

    /// Returns the address of the Jetton Master contract.
    pub fn address(&self) -> &MsgAddress {
        &self.address
    }

    /// Returns the address as a JettonMasterAddress.
    pub fn jetton_address(&self) -> JettonMasterAddress {
        JettonMasterAddress::new(self.address.clone())
    }

    /// Gets jetton data from the contract.
    ///
    /// Calls the `get_jetton_data` get method which returns:
    /// - total_supply: u128
    /// - mintable: bool (-1 = true, 0 = false)
    /// - admin_address: MsgAddress
    /// - content: Cell (TEP-64 content)
    /// - wallet_code: Cell
    pub async fn get_jetton_data(&self, client: &LiteClient) -> JettonResult<JettonData> {
        let account_addr = msg_address_to_account(&self.address)?;

        let result = client
            .run_get_method_by_name(&account_addr, "get_jetton_data", &[])
            .await
            .map_err(|e| JettonError::NetworkError(e.to_string()))?;

        parse_jetton_data(&result)
    }

    /// Gets the wallet address for a specific owner.
    ///
    /// Calls the `get_wallet_address` get method with the owner's address.
    pub async fn get_wallet_address(
        &self,
        client: &LiteClient,
        owner: &MsgAddress,
    ) -> JettonResult<JettonWalletAddress> {
        let account_addr = msg_address_to_account(&self.address)?;

        // Build the owner address as a slice parameter
        let owner_cell = build_address_cell(owner)?;
        let params = BagOfCells::from_root(owner_cell).serialize()?;

        let result = client
            .run_get_method(&result_block_id(client).await?, &account_addr,
                           compute_method_id("get_wallet_address"), &params, 4)
            .await
            .map_err(|e| JettonError::NetworkError(e.to_string()))?;

        parse_wallet_address(&result)
    }
}

impl From<MsgAddress> for JettonMaster {
    fn from(address: MsgAddress) -> Self {
        Self::new(address)
    }
}

impl From<JettonMasterAddress> for JettonMaster {
    fn from(address: JettonMasterAddress) -> Self {
        Self::from_address(address)
    }
}

/// Converts a MsgAddress to AccountAddress.
fn msg_address_to_account(addr: &MsgAddress) -> JettonResult<AccountAddress> {
    match addr {
        MsgAddress::Internal { workchain, address } => {
            Ok(AccountAddress::new(*workchain, *address))
        }
        _ => Err(JettonError::InvalidAddress(
            "Only internal addresses are supported".to_string(),
        )),
    }
}

/// Builds an address cell for use as a get method parameter.
pub fn build_address_cell(addr: &MsgAddress) -> JettonResult<Cell> {
    let mut builder = CellBuilder::new();
    builder.store_address(addr)?;
    Ok(builder.build()?)
}

/// Parses an address from a cell/slice.
pub fn parse_address_from_slice(cell: &Cell) -> JettonResult<MsgAddress> {
    let mut slice = CellSlice::new(cell);
    Ok(slice.load_address()?)
}

/// Gets the latest block ID for running get methods.
async fn result_block_id(client: &LiteClient) -> JettonResult<ton_adnl::BlockIdExt> {
    let mc_info = client
        .get_masterchain_info()
        .await
        .map_err(|e| JettonError::NetworkError(e.to_string()))?;
    Ok(mc_info.last)
}

/// Computes a get method ID from its name.
fn compute_method_id(name: &str) -> u64 {
    ton_adnl::compute_method_id(name)
}

/// Parses the result of get_jetton_data.
fn parse_jetton_data(result: &RunMethodResult) -> JettonResult<JettonData> {
    if result.exit_code != 0 {
        return Err(JettonError::GetMethodFailed(result.exit_code));
    }

    // Parse the result stack
    // Stack order (from bottom to top): [total_supply, mintable, admin_address, content, wallet_code]
    let result_data = result.result.as_ref()
        .ok_or_else(|| JettonError::UnexpectedResult("No result data".to_string()))?;

    // Deserialize the stack from BoC
    let boc = BagOfCells::deserialize(result_data)?;
    let stack_cell = boc.single_root()
        .map_err(|_| JettonError::UnexpectedResult("Invalid stack BoC".to_string()))?;

    // The stack is encoded as a linked list of cells
    // For simplicity, we'll parse the expected values directly
    // A full implementation would properly parse the TVM stack format

    let mut slice = CellSlice::new(stack_cell);

    // Read depth (number of elements)
    let depth = slice.load_uint(24).map_err(|_| {
        JettonError::UnexpectedResult("Failed to read stack depth".to_string())
    })?;

    if depth < 5 {
        return Err(JettonError::StackUnderflow {
            expected: 5,
            actual: depth as usize,
        });
    }

    // Parse stack elements from the references
    // This is a simplified implementation - real stack parsing is more complex
    let entries = parse_stack_entries(stack_cell, 5)?;

    // Extract values from stack entries
    let total_supply = extract_int_as_u128(&entries[0])?;
    let mintable = extract_int_as_bool(&entries[1])?;
    let admin_address = extract_address(&entries[2])?;
    let content = extract_content(&entries[3])?;
    let wallet_code = extract_cell(&entries[4])?;

    Ok(JettonData {
        total_supply,
        mintable,
        admin_address,
        content,
        wallet_code,
    })
}

/// Parses the result of get_wallet_address.
fn parse_wallet_address(result: &RunMethodResult) -> JettonResult<JettonWalletAddress> {
    if result.exit_code != 0 {
        return Err(JettonError::GetMethodFailed(result.exit_code));
    }

    let result_data = result.result.as_ref()
        .ok_or_else(|| JettonError::UnexpectedResult("No result data".to_string()))?;

    let boc = BagOfCells::deserialize(result_data)?;
    let stack_cell = boc.single_root()
        .map_err(|_| JettonError::UnexpectedResult("Invalid stack BoC".to_string()))?;

    // Parse the stack to get the address slice
    let entries = parse_stack_entries(stack_cell, 1)?;
    let address = extract_address(&entries[0])?;

    Ok(JettonWalletAddress::new(address))
}

/// Stack entry representation for parsing.
#[derive(Debug)]
enum StackValue {
    Int(i128),
    Cell(Arc<Cell>),
    Slice(Arc<Cell>),
}

/// Parses stack entries from a stack cell.
fn parse_stack_entries(stack_cell: &Cell, expected: usize) -> JettonResult<Vec<StackValue>> {
    let mut entries = Vec::with_capacity(expected);

    // TVM stack is stored as a linked list:
    // stack#_ depth:uint24 elements:(VmStackList depth) = VmStack;
    // This is a simplified parser that handles the common cases

    let mut slice = CellSlice::new(stack_cell);

    // Skip depth field (already verified)
    let _ = slice.load_uint(24);

    // Parse elements from references
    // Each stack element is in a reference or inline based on type
    for i in 0..expected.min(stack_cell.reference_count()) {
        if let Some(entry_cell) = stack_cell.reference(i) {
            // Parse entry type and value
            let entry = parse_stack_entry(entry_cell)?;
            entries.push(entry);
        }
    }

    // If we have fewer entries than expected, return an error
    if entries.len() < expected {
        return Err(JettonError::StackUnderflow {
            expected,
            actual: entries.len(),
        });
    }

    Ok(entries)
}

/// Parses a single stack entry from a cell.
fn parse_stack_entry(cell: &Cell) -> JettonResult<StackValue> {
    let mut slice = CellSlice::new(cell);

    // Read entry type byte
    // Types: 0 = null, 1 = int64, 2 = int257, 3 = cell, 4 = slice, etc.
    if slice.bits_left() < 8 {
        return Err(JettonError::UnexpectedResult("Empty stack entry".to_string()));
    }

    let entry_type = slice.load_u8()?;

    match entry_type {
        0 => {
            // Null - treat as 0
            Ok(StackValue::Int(0))
        }
        1 => {
            // Int64
            let value = slice.load_i64()? as i128;
            Ok(StackValue::Int(value))
        }
        2 => {
            // Int257 - simplified parsing
            // Full implementation would handle 257-bit integers
            if slice.bits_left() >= 64 {
                let value = slice.load_i64()? as i128;
                Ok(StackValue::Int(value))
            } else {
                Ok(StackValue::Int(0))
            }
        }
        3 | 5 => {
            // Cell or Builder - read from reference
            if slice.refs_left() > 0 {
                let ref_cell = slice.load_ref()?;
                Ok(StackValue::Cell(Arc::new(ref_cell.clone())))
            } else {
                Err(JettonError::UnexpectedResult("Cell entry without reference".to_string()))
            }
        }
        4 => {
            // Slice - contains cell reference and bit/ref offsets
            if slice.refs_left() > 0 {
                let ref_cell = slice.load_ref()?;
                Ok(StackValue::Slice(Arc::new(ref_cell.clone())))
            } else {
                Err(JettonError::UnexpectedResult("Slice entry without reference".to_string()))
            }
        }
        _ => {
            // Unknown type - try to read as cell if there's a reference
            if cell.reference_count() > 0
                && let Some(ref_cell) = cell.reference(0) {
                    return Ok(StackValue::Cell(ref_cell.clone()));
                }
            Err(JettonError::UnexpectedResult(format!("Unknown stack entry type: {}", entry_type)))
        }
    }
}

/// Extracts an integer value as u128.
fn extract_int_as_u128(value: &StackValue) -> JettonResult<u128> {
    match value {
        StackValue::Int(n) => {
            if *n >= 0 {
                Ok(*n as u128)
            } else {
                Err(JettonError::UnexpectedResult("Negative value for u128".to_string()))
            }
        }
        _ => Err(JettonError::InvalidStackEntry {
            expected: "integer",
            actual: format!("{:?}", value),
        }),
    }
}

/// Extracts an integer value as bool (-1 = true, 0 = false).
fn extract_int_as_bool(value: &StackValue) -> JettonResult<bool> {
    match value {
        StackValue::Int(n) => Ok(*n != 0),
        _ => Err(JettonError::InvalidStackEntry {
            expected: "integer (bool)",
            actual: format!("{:?}", value),
        }),
    }
}

/// Extracts an address from a slice or cell value.
fn extract_address(value: &StackValue) -> JettonResult<MsgAddress> {
    match value {
        StackValue::Slice(cell) | StackValue::Cell(cell) => {
            parse_address_from_slice(cell)
        }
        StackValue::Int(_) => {
            // Some contracts return addr_none as 0
            Ok(MsgAddress::Null)
        }
    }
}

/// Extracts JettonContent from a cell value.
fn extract_content(value: &StackValue) -> JettonResult<JettonContent> {
    match value {
        StackValue::Cell(cell) => JettonContent::from_cell(cell),
        _ => Err(JettonError::InvalidStackEntry {
            expected: "cell",
            actual: format!("{:?}", value),
        }),
    }
}

/// Extracts a cell value.
fn extract_cell(value: &StackValue) -> JettonResult<Arc<Cell>> {
    match value {
        StackValue::Cell(cell) => Ok(cell.clone()),
        _ => Err(JettonError::InvalidStackEntry {
            expected: "cell",
            actual: format!("{:?}", value),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_jetton_master_new() {
        let addr = MsgAddress::Internal {
            workchain: 0,
            address: [0xAB; 32],
        };
        let master = JettonMaster::new(addr.clone());

        assert_eq!(master.address(), &addr);
    }

    #[test]
    fn test_jetton_master_from_address() {
        let addr = MsgAddress::Internal {
            workchain: -1,
            address: [0xCD; 32],
        };
        let master_addr = JettonMasterAddress::new(addr.clone());
        let master = JettonMaster::from_address(master_addr);

        assert_eq!(master.address(), &addr);
    }

    #[test]
    fn test_jetton_address() {
        let addr = MsgAddress::Internal {
            workchain: 0,
            address: [0x12; 32],
        };
        let master = JettonMaster::new(addr.clone());

        let jetton_addr = master.jetton_address();
        assert_eq!(jetton_addr.address(), &addr);
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
    fn test_from_trait_implementations() {
        let addr = MsgAddress::Internal {
            workchain: 0,
            address: [0x78; 32],
        };

        // From MsgAddress
        let master1: JettonMaster = addr.clone().into();
        assert_eq!(master1.address(), &addr);

        // From JettonMasterAddress
        let master_addr = JettonMasterAddress::new(addr.clone());
        let master2: JettonMaster = master_addr.into();
        assert_eq!(master2.address(), &addr);
    }
}
