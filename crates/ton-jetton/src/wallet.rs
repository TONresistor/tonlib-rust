//! Jetton Wallet contract interface.
//!
//! The Jetton Wallet contract holds a user's token balance and handles transfers.
//! Each user has their own Jetton Wallet for each Jetton they hold.

use std::sync::Arc;

use ton_adnl::{AccountAddress, LiteClient, RunMethodResult};
use ton_cell::{BagOfCells, Cell, CellBuilder, CellSlice, MsgAddress};

use crate::error::{JettonError, JettonResult};
use crate::master::parse_address_from_slice;
use crate::types::{JettonWalletAddress, JettonWalletData};

/// TEP-74 Operation codes.
pub mod opcodes {
    /// Transfer tokens to another address.
    pub const OP_TRANSFER: u32 = 0x0f8a7ea5;

    /// Notification of incoming transfer.
    pub const OP_TRANSFER_NOTIFICATION: u32 = 0x7362d09c;

    /// Internal transfer between wallets.
    pub const OP_INTERNAL_TRANSFER: u32 = 0x178d4519;

    /// Return excess TON after operation.
    pub const OP_EXCESSES: u32 = 0xd53276db;

    /// Burn tokens.
    pub const OP_BURN: u32 = 0x595f07bc;

    /// Notification of burned tokens.
    pub const OP_BURN_NOTIFICATION: u32 = 0x7bdd97de;
}

pub use opcodes::*;

/// Jetton Wallet contract interface.
///
/// Provides methods to interact with a TEP-74 Jetton Wallet contract.
#[derive(Debug, Clone)]
pub struct JettonWallet {
    /// Address of the Jetton Wallet contract.
    address: MsgAddress,
}

impl JettonWallet {
    /// Creates a new JettonWallet instance.
    pub fn new(address: MsgAddress) -> Self {
        Self { address }
    }

    /// Creates a new JettonWallet from a JettonWalletAddress.
    pub fn from_address(address: JettonWalletAddress) -> Self {
        Self {
            address: address.into_inner(),
        }
    }

    /// Returns the address of the Jetton Wallet contract.
    pub fn address(&self) -> &MsgAddress {
        &self.address
    }

    /// Returns the address as a JettonWalletAddress.
    pub fn wallet_address(&self) -> JettonWalletAddress {
        JettonWalletAddress::new(self.address.clone())
    }

    /// Gets wallet data from the contract.
    ///
    /// Calls the `get_wallet_data` get method which returns:
    /// - balance: u128
    /// - owner: MsgAddress
    /// - jetton_master: MsgAddress
    /// - wallet_code: Cell
    pub async fn get_wallet_data(&self, client: &LiteClient) -> JettonResult<JettonWalletData> {
        let account_addr = msg_address_to_account(&self.address)?;

        let result = client
            .run_get_method_by_name(&account_addr, "get_wallet_data", &[])
            .await
            .map_err(|e| JettonError::NetworkError(e.to_string()))?;

        parse_wallet_data(&result)
    }

    /// Creates a transfer message body.
    ///
    /// # Arguments
    ///
    /// * `query_id` - Query ID for response tracking
    /// * `amount` - Amount of tokens to transfer (in smallest units)
    /// * `destination` - Recipient's address
    /// * `response_destination` - Address for excess TON return
    /// * `custom_payload` - Optional custom payload cell
    /// * `forward_ton_amount` - Amount of TON to forward with notification
    /// * `forward_payload` - Optional payload to forward with notification
    ///
    /// # Message Format
    ///
    /// ```text
    /// transfer#0f8a7ea5
    ///   query_id:uint64
    ///   amount:(VarUInteger 16)
    ///   destination:MsgAddress
    ///   response_destination:MsgAddress
    ///   custom_payload:(Maybe ^Cell)
    ///   forward_ton_amount:(VarUInteger 16)
    ///   forward_payload:(Either Cell ^Cell)
    /// ```
    pub fn create_transfer_body(
        query_id: u64,
        amount: u128,
        destination: &MsgAddress,
        response_destination: &MsgAddress,
        custom_payload: Option<Cell>,
        forward_ton_amount: u128,
        forward_payload: Option<Cell>,
    ) -> JettonResult<Cell> {
        let mut builder = CellBuilder::new();

        // op::transfer
        builder.store_u32(OP_TRANSFER)?;

        // query_id
        builder.store_u64(query_id)?;

        // amount (VarUInteger 16 = Coins)
        builder.store_coins(amount)?;

        // destination
        builder.store_address(destination)?;

        // response_destination
        builder.store_address(response_destination)?;

        // custom_payload (Maybe ^Cell)
        if let Some(payload) = custom_payload {
            builder.store_bit(true)?;
            builder.store_ref(Arc::new(payload))?;
        } else {
            builder.store_bit(false)?;
        }

        // forward_ton_amount
        builder.store_coins(forward_ton_amount)?;

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

    /// Creates a burn message body.
    ///
    /// # Arguments
    ///
    /// * `query_id` - Query ID for response tracking
    /// * `amount` - Amount of tokens to burn (in smallest units)
    /// * `response_destination` - Address for burn notification
    /// * `custom_payload` - Optional custom payload cell
    ///
    /// # Message Format
    ///
    /// ```text
    /// burn#595f07bc
    ///   query_id:uint64
    ///   amount:(VarUInteger 16)
    ///   response_destination:MsgAddress
    ///   custom_payload:(Maybe ^Cell)
    /// ```
    pub fn create_burn_body(
        query_id: u64,
        amount: u128,
        response_destination: &MsgAddress,
        custom_payload: Option<Cell>,
    ) -> JettonResult<Cell> {
        let mut builder = CellBuilder::new();

        // op::burn
        builder.store_u32(OP_BURN)?;

        // query_id
        builder.store_u64(query_id)?;

        // amount
        builder.store_coins(amount)?;

        // response_destination
        builder.store_address(response_destination)?;

        // custom_payload (Maybe ^Cell)
        if let Some(payload) = custom_payload {
            builder.store_bit(true)?;
            builder.store_ref(Arc::new(payload))?;
        } else {
            builder.store_bit(false)?;
        }

        Ok(builder.build()?)
    }
}

impl From<MsgAddress> for JettonWallet {
    fn from(address: MsgAddress) -> Self {
        Self::new(address)
    }
}

impl From<JettonWalletAddress> for JettonWallet {
    fn from(address: JettonWalletAddress) -> Self {
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

/// Parses the result of get_wallet_data.
fn parse_wallet_data(result: &RunMethodResult) -> JettonResult<JettonWalletData> {
    if result.exit_code != 0 {
        return Err(JettonError::GetMethodFailed(result.exit_code));
    }

    let result_data = result.result.as_ref()
        .ok_or_else(|| JettonError::UnexpectedResult("No result data".to_string()))?;

    let boc = BagOfCells::deserialize(result_data)?;
    let stack_cell = boc.single_root()
        .map_err(|_| JettonError::UnexpectedResult("Invalid stack BoC".to_string()))?;

    // Parse stack: [balance, owner, jetton_master, wallet_code]
    let entries = parse_stack_entries(stack_cell, 4)?;

    let balance = extract_int_as_u128(&entries[0])?;
    let owner = extract_address(&entries[1])?;
    let jetton_master = extract_address(&entries[2])?;
    let wallet_code = extract_cell(&entries[3])?;

    Ok(JettonWalletData {
        balance,
        owner,
        jetton_master,
        wallet_code,
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
fn parse_stack_entries(stack_cell: &Cell, expected: usize) -> JettonResult<Vec<StackValue>> {
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

    if slice.bits_left() < 8 {
        return Err(JettonError::UnexpectedResult("Empty stack entry".to_string()));
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
                Err(JettonError::UnexpectedResult("Cell entry without reference".to_string()))
            }
        }
        4 => {
            if slice.refs_left() > 0 {
                let ref_cell = slice.load_ref()?;
                Ok(StackValue::Slice(Arc::new(ref_cell.clone())))
            } else {
                Err(JettonError::UnexpectedResult("Slice entry without reference".to_string()))
            }
        }
        _ => {
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

/// Extracts an address from a slice or cell value.
fn extract_address(value: &StackValue) -> JettonResult<MsgAddress> {
    match value {
        StackValue::Slice(cell) | StackValue::Cell(cell) => {
            parse_address_from_slice(cell)
        }
        StackValue::Int(_) => {
            Ok(MsgAddress::Null)
        }
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

/// Creates a comment cell for use as forward_payload.
///
/// This creates a cell with a text comment that will be shown
/// in wallet applications when receiving the transfer notification.
pub fn build_comment_cell(comment: &str) -> JettonResult<Cell> {
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
    fn test_jetton_wallet_new() {
        let addr = MsgAddress::Internal {
            workchain: 0,
            address: [0xAB; 32],
        };
        let wallet = JettonWallet::new(addr.clone());

        assert_eq!(wallet.address(), &addr);
    }

    #[test]
    fn test_jetton_wallet_from_address() {
        let addr = MsgAddress::Internal {
            workchain: -1,
            address: [0xCD; 32],
        };
        let wallet_addr = JettonWalletAddress::new(addr.clone());
        let wallet = JettonWallet::from_address(wallet_addr);

        assert_eq!(wallet.address(), &addr);
    }

    #[test]
    fn test_create_transfer_body() {
        let destination = MsgAddress::Internal {
            workchain: 0,
            address: [0x12; 32],
        };
        let response_dest = MsgAddress::Internal {
            workchain: 0,
            address: [0x34; 32],
        };

        let body = JettonWallet::create_transfer_body(
            12345,                      // query_id
            1_000_000_000,             // amount (1 token with 9 decimals)
            &destination,
            &response_dest,
            None,                       // custom_payload
            50_000_000,                // forward_ton_amount (0.05 TON)
            None,                       // forward_payload
        ).unwrap();

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
        let destination = MsgAddress::Internal {
            workchain: 0,
            address: [0x56; 32],
        };
        let response_dest = MsgAddress::Internal {
            workchain: 0,
            address: [0x78; 32],
        };

        let comment = build_comment_cell("Hello").unwrap();

        let body = JettonWallet::create_transfer_body(
            0,
            500_000_000,
            &destination,
            &response_dest,
            None,
            100_000_000,
            Some(comment),
        ).unwrap();

        // Verify the cell has a reference (for forward_payload)
        assert!(body.reference_count() > 0);
    }

    #[test]
    fn test_create_burn_body() {
        let response_dest = MsgAddress::Internal {
            workchain: 0,
            address: [0x9A; 32],
        };

        let body = JettonWallet::create_burn_body(
            99999,                      // query_id
            2_000_000_000,             // amount (2 tokens)
            &response_dest,
            None,                       // custom_payload
        ).unwrap();

        // Parse and verify
        let mut slice = CellSlice::new(&body);
        let opcode = slice.load_u32().unwrap();
        assert_eq!(opcode, OP_BURN);

        let query_id = slice.load_u64().unwrap();
        assert_eq!(query_id, 99999);
    }

    #[test]
    fn test_create_burn_body_with_payload() {
        let response_dest = MsgAddress::Internal {
            workchain: 0,
            address: [0xBC; 32],
        };

        let custom = CellBuilder::new().build().unwrap();

        let body = JettonWallet::create_burn_body(
            0,
            100_000_000,
            &response_dest,
            Some(custom),
        ).unwrap();

        // Verify the cell has a reference (for custom_payload)
        assert!(body.reference_count() > 0);
    }

    #[test]
    fn test_build_comment_cell() {
        let comment = "Test transfer";
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
        assert_eq!(OP_TRANSFER, 0x0f8a7ea5);
        assert_eq!(OP_TRANSFER_NOTIFICATION, 0x7362d09c);
        assert_eq!(OP_INTERNAL_TRANSFER, 0x178d4519);
        assert_eq!(OP_EXCESSES, 0xd53276db);
        assert_eq!(OP_BURN, 0x595f07bc);
        assert_eq!(OP_BURN_NOTIFICATION, 0x7bdd97de);
    }

    #[test]
    fn test_from_trait_implementations() {
        let addr = MsgAddress::Internal {
            workchain: 0,
            address: [0xDE; 32],
        };

        // From MsgAddress
        let wallet1: JettonWallet = addr.clone().into();
        assert_eq!(wallet1.address(), &addr);

        // From JettonWalletAddress
        let wallet_addr = JettonWalletAddress::new(addr.clone());
        let wallet2: JettonWallet = wallet_addr.into();
        assert_eq!(wallet2.address(), &addr);
    }
}
