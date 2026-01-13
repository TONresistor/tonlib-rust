//! Core Jetton types.
//!
//! This module defines the fundamental types for TEP-74 Jetton standard.

use std::sync::Arc;

use ton_cell::{Cell, MsgAddress};

use crate::metadata::JettonContent;

/// Jetton Master contract address.
///
/// Wraps a MsgAddress to provide type safety for Jetton Master addresses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JettonMasterAddress(pub MsgAddress);

impl JettonMasterAddress {
    /// Creates a new JettonMasterAddress.
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

impl From<MsgAddress> for JettonMasterAddress {
    fn from(addr: MsgAddress) -> Self {
        Self(addr)
    }
}

impl std::fmt::Display for JettonMasterAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Jetton Wallet contract address.
///
/// Wraps a MsgAddress to provide type safety for Jetton Wallet addresses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JettonWalletAddress(pub MsgAddress);

impl JettonWalletAddress {
    /// Creates a new JettonWalletAddress.
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

impl From<MsgAddress> for JettonWalletAddress {
    fn from(addr: MsgAddress) -> Self {
        Self(addr)
    }
}

impl std::fmt::Display for JettonWalletAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Data returned by the `get_jetton_data` get method on Jetton Master contract.
///
/// Contains all the information about a Jetton token.
#[derive(Debug, Clone)]
pub struct JettonData {
    /// Total supply of tokens (in smallest units).
    pub total_supply: u128,
    /// Whether new tokens can be minted.
    pub mintable: bool,
    /// Address of the admin/owner of the Jetton.
    pub admin_address: MsgAddress,
    /// Token metadata (TEP-64 content).
    pub content: JettonContent,
    /// Code of the Jetton Wallet contract.
    pub wallet_code: Arc<Cell>,
}

impl JettonData {
    /// Creates a new JettonData.
    pub fn new(
        total_supply: u128,
        mintable: bool,
        admin_address: MsgAddress,
        content: JettonContent,
        wallet_code: Arc<Cell>,
    ) -> Self {
        Self {
            total_supply,
            mintable,
            admin_address,
            content,
            wallet_code,
        }
    }
}

/// Data returned by the `get_wallet_data` get method on Jetton Wallet contract.
///
/// Contains the state of a user's Jetton wallet.
#[derive(Debug, Clone)]
pub struct JettonWalletData {
    /// Balance of tokens in this wallet (in smallest units).
    pub balance: u128,
    /// Address of the wallet owner.
    pub owner: MsgAddress,
    /// Address of the Jetton Master contract.
    pub jetton_master: MsgAddress,
    /// Code of the Jetton Wallet contract.
    pub wallet_code: Arc<Cell>,
}

impl JettonWalletData {
    /// Creates a new JettonWalletData.
    pub fn new(
        balance: u128,
        owner: MsgAddress,
        jetton_master: MsgAddress,
        wallet_code: Arc<Cell>,
    ) -> Self {
        Self {
            balance,
            owner,
            jetton_master,
            wallet_code,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_jetton_master_address() {
        let addr = MsgAddress::Internal {
            workchain: 0,
            address: [0xAB; 32],
        };
        let jetton_addr = JettonMasterAddress::new(addr.clone());

        assert_eq!(jetton_addr.address(), &addr);
        assert_eq!(jetton_addr.clone().into_inner(), addr);
    }

    #[test]
    fn test_jetton_wallet_address() {
        let addr = MsgAddress::Internal {
            workchain: 0,
            address: [0xCD; 32],
        };
        let wallet_addr = JettonWalletAddress::new(addr.clone());

        assert_eq!(wallet_addr.address(), &addr);
        assert_eq!(wallet_addr.clone().into_inner(), addr);
    }

    #[test]
    fn test_jetton_master_address_from() {
        let addr = MsgAddress::Internal {
            workchain: -1,
            address: [0x12; 32],
        };
        let jetton_addr: JettonMasterAddress = addr.clone().into();

        assert_eq!(jetton_addr.0, addr);
    }

    #[test]
    fn test_jetton_wallet_address_from() {
        let addr = MsgAddress::Internal {
            workchain: 0,
            address: [0x34; 32],
        };
        let wallet_addr: JettonWalletAddress = addr.clone().into();

        assert_eq!(wallet_addr.0, addr);
    }
}
