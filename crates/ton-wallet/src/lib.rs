//! TON Wallet implementations
//!
//! This crate provides wallet implementations for the TON blockchain:
//! - Wallet V3R2: Standard wallet with subwallet ID
//! - Wallet V4R2: With plugin support
//! - Wallet V5R1: Latest wallet with extended features (W5)
//! - Highload V2R2: For mass transfers (up to 254 messages)

pub mod codes;
pub mod error;
pub mod highload;
pub mod mnemonic;
pub mod transfer;
pub mod v3r2;
pub mod v4r2;
pub mod v5r1;
pub mod wallet;

// Re-exports
pub use error::{WalletError, WalletResult};
pub use highload::HighloadV2R2;
pub use mnemonic::Mnemonic;
pub use transfer::{build_comment, Transfer};
pub use v3r2::WalletV3R2;
pub use v4r2::WalletV4R2;
pub use v5r1::WalletV5R1;
pub use wallet::Wallet;

#[cfg(test)]
mod tests {
    use super::*;
    use ton_cell::MsgAddress;

    #[test]
    fn test_full_flow() {
        let mnemonic = Mnemonic::generate_unchecked();
        assert!(mnemonic.is_valid());
        let keypair = mnemonic.to_keypair();
        let wallet = WalletV3R2::new(keypair, 0).unwrap();
        let transfer = Transfer::new(MsgAddress::Null, 1_000_000_000);
        let body = wallet.create_transfer_body(0, &[transfer], u32::MAX).unwrap();
        let signed = wallet.sign(&body).unwrap();
        let ext_msg = wallet.create_external_message(&signed).unwrap();
        assert!(ext_msg.bit_len() > 0);
    }

    #[test]
    fn test_different_wallet_versions() {
        let keypair = ton_crypto::Ed25519Keypair::generate();
        let v3 = WalletV3R2::new(keypair.clone(), 0).unwrap();
        let v4 = WalletV4R2::new(keypair.clone(), 0).unwrap();
        let v5 = WalletV5R1::new(keypair.clone(), 0).unwrap();
        let hl = HighloadV2R2::new(keypair, 0).unwrap();
        assert_ne!(v3.address(), v4.address());
        assert_ne!(v4.address(), v5.address());
        assert_ne!(v4.address(), hl.address());
    }

    #[test]
    fn test_mnemonic_roundtrip() {
        let mnemonic = Mnemonic::generate_unchecked();
        let phrase = mnemonic.to_phrase();
        let restored = Mnemonic::from_phrase(&phrase).unwrap();
        assert_eq!(mnemonic.words(), restored.words());
        let k1 = mnemonic.to_keypair();
        let k2 = restored.to_keypair();
        assert_eq!(k1.public_key, k2.public_key);
    }
}
