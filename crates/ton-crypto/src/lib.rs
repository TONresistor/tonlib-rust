//! TON Cryptography Library
//!
//! This crate provides cryptographic primitives used in the TON network:
//!
//! - **Ed25519**: Digital signatures for authentication and message signing
//! - **X25519**: ECDH key exchange for establishing shared secrets
//! - **AES-CTR**: Symmetric encryption for ADNL message encryption
//! - **SHA256**: Hashing for message digests and key IDs
//! - **Key IDs**: ADNL address calculation from public keys
//!
//! # Overview
//!
//! The TON network uses a layered cryptographic approach:
//!
//! 1. **Identity**: Ed25519 keypairs identify nodes and sign messages
//! 2. **Key Exchange**: X25519 ECDH establishes shared secrets between peers
//! 3. **Encryption**: AES-256-CTR encrypts ADNL channel messages
//! 4. **Addressing**: Key IDs (SHA256 of TL-serialized public keys) serve as ADNL addresses
//!
//! # Example: Establishing an Encrypted Channel
//!
//! ```
//! use ton_crypto::{ed25519::Ed25519Keypair, x25519::X25519Keypair, aes_ctr::AesCtrCipher, keys::calculate_key_id};
//!
//! // Each peer has an Ed25519 identity keypair
//! let alice_identity = Ed25519Keypair::generate();
//! let bob_identity = Ed25519Keypair::generate();
//!
//! // Calculate ADNL addresses (key IDs)
//! let alice_addr = calculate_key_id(&alice_identity.public_key);
//! let bob_addr = calculate_key_id(&bob_identity.public_key);
//!
//! // For channel encryption, use X25519 key exchange
//! let alice_channel = X25519Keypair::generate();
//! let bob_channel = X25519Keypair::generate();
//!
//! // Both derive the same shared secret
//! let alice_shared = alice_channel.ecdh(&bob_channel.public_key);
//! let bob_shared = bob_channel.ecdh(&alice_channel.public_key);
//! assert_eq!(alice_shared, bob_shared);
//!
//! // Use the shared secret to derive encryption keys
//! // (In practice, you'd use a KDF here)
//! let key = alice_shared;
//! let iv = [0u8; 16]; // In practice, use a proper nonce
//!
//! // Encrypt a message
//! let mut cipher = AesCtrCipher::new(key, iv);
//! let ciphertext = cipher.encrypt(b"Hello, TON!");
//! ```

pub mod aes_ctr;
pub mod ed25519;
pub mod kdf;
pub mod keys;
pub mod sha256;
pub mod x25519;

// Re-export main types for convenience
pub use aes_ctr::{
    aes_ctr_cipher_adnl, aes_ctr_decrypt, aes_ctr_encrypt, derive_aes_params_adnl, AesCtrCipher,
    AesCtrError,
};
pub use ed25519::{verify_signature, Ed25519Error, Ed25519Keypair};
pub use keys::{calculate_key_id, KeyId};
pub use kdf::{hmac_sha256, hmac_sha512, pbkdf2_sha256, pbkdf2_sha512};
pub use sha256::{sha256, sha256_multi, Sha256Hasher};
pub use x25519::{
    ecdh, ecdh_ed25519, ed25519_to_x25519_private, ed25519_to_x25519_public, X25519Error,
    X25519Keypair,
};

/// Generate a cryptographically secure random 32-byte array.
///
/// This is useful for generating random keys, nonces, etc.
pub fn random_bytes_32() -> [u8; 32] {
    use rand::RngCore;
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    bytes
}

/// Generate a cryptographically secure random 16-byte array.
///
/// This is useful for generating IVs/nonces.
pub fn random_bytes_16() -> [u8; 16] {
    use rand::RngCore;
    let mut bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut bytes);
    bytes
}

/// Fill a slice with cryptographically secure random bytes.
pub fn fill_random(dest: &mut [u8]) {
    use rand::RngCore;
    rand::thread_rng().fill_bytes(dest);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_full_crypto_flow() {
        // Generate identity keypairs
        let alice = Ed25519Keypair::generate();
        let bob = Ed25519Keypair::generate();

        // Calculate ADNL addresses
        let alice_addr = calculate_key_id(&alice.public_key);
        let bob_addr = calculate_key_id(&bob.public_key);
        assert_ne!(alice_addr, bob_addr);

        // Sign a message with identity key
        let message = b"Hello, TON!";
        let signature = alice.sign(message);
        assert!(verify_signature(&alice.public_key, message, &signature).is_ok());

        // Establish shared secret with X25519
        let alice_x = X25519Keypair::generate();
        let bob_x = X25519Keypair::generate();

        let alice_shared = alice_x.ecdh(&bob_x.public_key);
        let bob_shared = bob_x.ecdh(&alice_x.public_key);
        assert_eq!(alice_shared, bob_shared);

        // Encrypt with AES-CTR
        let iv = random_bytes_16();
        let mut alice_cipher = AesCtrCipher::new(alice_shared, iv);
        let ciphertext = alice_cipher.encrypt(message);

        let mut bob_cipher = AesCtrCipher::new(bob_shared, iv);
        let decrypted = bob_cipher.decrypt(&ciphertext);

        assert_eq!(message.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_random_bytes() {
        let bytes1 = random_bytes_32();
        let bytes2 = random_bytes_32();

        // Random bytes should be different (with overwhelming probability)
        assert_ne!(bytes1, bytes2);
        assert_eq!(bytes1.len(), 32);
    }

    #[test]
    fn test_random_bytes_16() {
        let bytes1 = random_bytes_16();
        let bytes2 = random_bytes_16();

        assert_ne!(bytes1, bytes2);
        assert_eq!(bytes1.len(), 16);
    }
}
