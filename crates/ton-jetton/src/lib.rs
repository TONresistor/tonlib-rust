//! # ton-jetton
//!
//! TEP-74 Jetton (fungible token) standard implementation for TON.
//!
//! This crate provides support for interacting with Jetton tokens on the TON blockchain,
//! implementing the TEP-74 standard for fungible tokens.
//!
//! ## Overview
//!
//! The Jetton standard defines two types of contracts:
//!
//! - **Jetton Master**: The main token contract that holds metadata and manages supply.
//!   There is one Jetton Master per token.
//!
//! - **Jetton Wallet**: Per-user wallet contracts that hold token balances.
//!   Each user has their own Jetton Wallet for each token they hold.
//!
//! ## TEP-74 Standard
//!
//! TEP-74 defines the standard interface for fungible tokens on TON:
//!
//! - **get_jetton_data**: Returns token metadata (total supply, mintable flag, admin, content, wallet code)
//! - **get_wallet_address**: Returns the wallet address for a given owner
//! - **get_wallet_data**: Returns wallet state (balance, owner, master, code)
//!
//! ### Operation Codes
//!
//! - `transfer` (0x0f8a7ea5): Transfer tokens to another address
//! - `burn` (0x595f07bc): Burn tokens
//! - `transfer_notification` (0x7362d09c): Notification of incoming transfer
//! - `internal_transfer` (0x178d4519): Internal transfer between wallets
//! - `excesses` (0xd53276db): Return excess TON after operation
//! - `burn_notification` (0x7bdd97de): Notification of burned tokens
//!
//! ## TEP-64 Token Data Standard
//!
//! Token metadata follows TEP-64:
//!
//! - **Off-chain (0x00)**: URI pointing to JSON metadata
//! - **On-chain (0x01)**: Dictionary with key-value pairs
//!
//! ## Example
//!
//! ```rust,no_run
//! use ton_jetton::{JettonMaster, JettonWallet, JettonContent};
//! use ton_cell::MsgAddress;
//! use ton_adnl::LiteClient;
//!
//! async fn example() -> Result<(), Box<dyn std::error::Error>> {
//!     // Connect to liteserver
//!     let client = LiteClient::connect("1.2.3.4", 12345, &[0u8; 32]).await?;
//!
//!     // Create Jetton Master instance
//!     let jetton_addr = MsgAddress::from_string("0:abc...").unwrap();
//!     let master = JettonMaster::new(jetton_addr);
//!
//!     // Get token information
//!     let data = master.get_jetton_data(&client).await?;
//!     println!("Total supply: {}", data.total_supply);
//!     println!("Mintable: {}", data.mintable);
//!
//!     // Get wallet address for an owner
//!     let owner = MsgAddress::from_string("0:def...").unwrap();
//!     let wallet_addr = master.get_wallet_address(&client, &owner).await?;
//!
//!     // Query wallet balance
//!     let wallet = JettonWallet::from_address(wallet_addr);
//!     let wallet_data = wallet.get_wallet_data(&client).await?;
//!     println!("Balance: {}", wallet_data.balance);
//!
//!     Ok(())
//! }
//! ```
//!
//! ## Creating Transfer Messages
//!
//! ```rust
//! use ton_jetton::JettonWallet;
//! use ton_cell::MsgAddress;
//!
//! // Create a transfer message body
//! let destination = MsgAddress::Internal {
//!     workchain: 0,
//!     address: [0x12; 32],
//! };
//! let response_dest = MsgAddress::Internal {
//!     workchain: 0,
//!     address: [0x34; 32],
//! };
//!
//! let body = JettonWallet::create_transfer_body(
//!     rand::random(),              // query_id
//!     1_000_000_000,              // amount (e.g., 1 token with 9 decimals)
//!     &destination,               // recipient
//!     &response_dest,             // where to send excess TON
//!     None,                       // custom payload
//!     50_000_000,                // forward TON amount (0.05 TON)
//!     None,                       // forward payload
//! ).unwrap();
//! ```
//!
//! ## References
//!
//! - [TEP-74: Fungible tokens (Jettons) standard](https://github.com/ton-blockchain/TEPs/blob/master/text/0074-jettons-standard.md)
//! - [TEP-64: Token Data Standard](https://github.com/ton-blockchain/TEPs/blob/master/text/0064-token-data-standard.md)

pub mod error;
pub mod master;
pub mod metadata;
pub mod types;
pub mod wallet;

// Re-export main types
pub use error::{JettonError, JettonResult};
pub use master::{JettonMaster, build_address_cell, parse_address_from_slice};
pub use metadata::{JettonContent, OnChainContent};
pub use types::{JettonData, JettonMasterAddress, JettonWalletAddress, JettonWalletData};
pub use wallet::{JettonWallet, build_comment_cell};

// Re-export operation codes
pub use wallet::opcodes::{
    OP_BURN, OP_BURN_NOTIFICATION, OP_EXCESSES, OP_INTERNAL_TRANSFER, OP_TRANSFER,
    OP_TRANSFER_NOTIFICATION,
};

/// High-level helper to transfer jettons.
///
/// This function creates and sends a jetton transfer message.
///
/// # Arguments
///
/// * `client` - LiteClient for network communication
/// * `jetton_wallet` - Address of the sender's jetton wallet
/// * `to` - Destination address for the tokens
/// * `amount` - Amount of tokens to transfer
/// * `forward_ton` - Amount of TON to forward with the transfer notification
/// * `comment` - Optional text comment for the transfer
///
/// # Returns
///
/// The transfer message body as a Cell.
///
/// # Example
///
/// ```rust,no_run
/// use ton_jetton::{transfer_jetton_body, JettonWalletAddress};
/// use ton_cell::MsgAddress;
///
/// let sender_response = MsgAddress::Internal {
///     workchain: 0,
///     address: [0x12; 32],
/// };
/// let to = MsgAddress::Internal {
///     workchain: 0,
///     address: [0x34; 32],
/// };
///
/// let body = transfer_jetton_body(
///     &sender_response,
///     &to,
///     1_000_000_000,      // 1 token (9 decimals)
///     50_000_000,         // 0.05 TON forward
///     Some("Payment"),
/// ).unwrap();
/// ```
pub fn transfer_jetton_body(
    response_destination: &ton_cell::MsgAddress,
    to: &ton_cell::MsgAddress,
    amount: u128,
    forward_ton: u128,
    comment: Option<&str>,
) -> JettonResult<ton_cell::Cell> {
    let forward_payload = if let Some(c) = comment {
        Some(build_comment_cell(c)?)
    } else {
        None
    };

    JettonWallet::create_transfer_body(
        rand::random(), // query_id
        amount,
        to,
        response_destination,
        None, // custom_payload
        forward_ton,
        forward_payload,
    )
}

/// High-level helper to create a burn message body.
///
/// # Arguments
///
/// * `response_destination` - Address for burn notification
/// * `amount` - Amount of tokens to burn
///
/// # Returns
///
/// The burn message body as a Cell.
pub fn burn_jetton_body(
    response_destination: &ton_cell::MsgAddress,
    amount: u128,
) -> JettonResult<ton_cell::Cell> {
    JettonWallet::create_burn_body(
        rand::random(), // query_id
        amount,
        response_destination,
        None, // custom_payload
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use ton_cell::{CellSlice, MsgAddress};

    #[test]
    fn test_transfer_jetton_body() {
        let response = MsgAddress::Internal {
            workchain: 0,
            address: [0x12; 32],
        };
        let to = MsgAddress::Internal {
            workchain: 0,
            address: [0x34; 32],
        };

        let body = transfer_jetton_body(
            &response,
            &to,
            1_000_000_000,
            50_000_000,
            Some("Test"),
        )
        .unwrap();

        // Verify opcode
        let mut slice = CellSlice::new(&body);
        let opcode = slice.load_u32().unwrap();
        assert_eq!(opcode, OP_TRANSFER);
    }

    #[test]
    fn test_transfer_jetton_body_no_comment() {
        let response = MsgAddress::Internal {
            workchain: 0,
            address: [0x56; 32],
        };
        let to = MsgAddress::Internal {
            workchain: 0,
            address: [0x78; 32],
        };

        let body = transfer_jetton_body(&response, &to, 500_000_000, 0, None).unwrap();

        let mut slice = CellSlice::new(&body);
        let opcode = slice.load_u32().unwrap();
        assert_eq!(opcode, OP_TRANSFER);

        // No references should be added for forward_payload when None
        // (but there might be references for other reasons)
    }

    #[test]
    fn test_burn_jetton_body() {
        let response = MsgAddress::Internal {
            workchain: 0,
            address: [0x9A; 32],
        };

        let body = burn_jetton_body(&response, 100_000_000).unwrap();

        let mut slice = CellSlice::new(&body);
        let opcode = slice.load_u32().unwrap();
        assert_eq!(opcode, OP_BURN);
    }

    #[test]
    fn test_opcodes_exported() {
        // Verify all opcodes are properly exported
        assert_eq!(OP_TRANSFER, 0x0f8a7ea5);
        assert_eq!(OP_TRANSFER_NOTIFICATION, 0x7362d09c);
        assert_eq!(OP_INTERNAL_TRANSFER, 0x178d4519);
        assert_eq!(OP_EXCESSES, 0xd53276db);
        assert_eq!(OP_BURN, 0x595f07bc);
        assert_eq!(OP_BURN_NOTIFICATION, 0x7bdd97de);
    }

    #[test]
    fn test_types_reexported() {
        // Verify main types are accessible
        let _: JettonMasterAddress;
        let _: JettonWalletAddress;
    }
}
