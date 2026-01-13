//! Ed25519 signature implementation for TON.
//!
//! This module provides Ed25519 digital signatures, which are used throughout
//! the TON protocol for authentication and message signing.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Errors that can occur during Ed25519 operations.
#[derive(Debug, Error)]
pub enum Ed25519Error {
    /// The provided key bytes are invalid.
    #[error("Invalid key bytes: {0}")]
    InvalidKey(String),

    /// The signature verification failed.
    #[error("Signature verification failed")]
    VerificationFailed,

    /// The signature bytes are invalid.
    #[error("Invalid signature bytes")]
    InvalidSignature,
}

/// An Ed25519 keypair for signing and verification.
///
/// The keypair consists of a 32-byte private key (seed) and a 32-byte public key.
/// The private key should be kept secret, while the public key can be shared.
///
/// # Example
/// ```
/// use ton_crypto::ed25519::Ed25519Keypair;
///
/// // Generate a new random keypair
/// let keypair = Ed25519Keypair::generate();
///
/// // Sign a message
/// let message = b"Hello, TON!";
/// let signature = keypair.sign(message);
///
/// // Verify the signature
/// assert!(keypair.verify(message, &signature).is_ok());
/// ```
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Ed25519Keypair {
    /// The 32-byte private key (seed). Zeroized on drop for security.
    private_key: [u8; 32],
    /// The 32-byte public key (not secret, skip zeroize).
    #[zeroize(skip)]
    pub public_key: [u8; 32],
    /// The internal signing key (skipped because SigningKey doesn't impl Zeroize,
    /// but private_key above contains the same secret and will be zeroized).
    #[zeroize(skip)]
    signing_key: SigningKey,
}

impl Ed25519Keypair {
    /// Generate a new random Ed25519 keypair.
    ///
    /// Uses the operating system's cryptographically secure random number generator.
    pub fn generate() -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();

        let mut private_key = [0u8; 32];
        private_key.copy_from_slice(signing_key.as_bytes());

        let mut public_key = [0u8; 32];
        public_key.copy_from_slice(verifying_key.as_bytes());

        Self {
            private_key,
            public_key,
            signing_key,
        }
    }

    /// Create a keypair from a 32-byte private key (seed).
    ///
    /// # Arguments
    /// * `private_key` - The 32-byte private key seed
    ///
    /// # Returns
    /// A new `Ed25519Keypair` with the derived public key
    pub fn from_private_key(private_key: [u8; 32]) -> Self {
        let signing_key = SigningKey::from_bytes(&private_key);
        let verifying_key = signing_key.verifying_key();

        let mut public_key = [0u8; 32];
        public_key.copy_from_slice(verifying_key.as_bytes());

        Self {
            private_key,
            public_key,
            signing_key,
        }
    }

    /// Create a keypair from a byte slice.
    ///
    /// # Arguments
    /// * `bytes` - A 32-byte slice containing the private key
    ///
    /// # Errors
    /// Returns an error if the slice is not exactly 32 bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Ed25519Error> {
        if bytes.len() != 32 {
            return Err(Ed25519Error::InvalidKey(format!(
                "Expected 32 bytes, got {}",
                bytes.len()
            )));
        }
        let mut private_key = [0u8; 32];
        private_key.copy_from_slice(bytes);
        Ok(Self::from_private_key(private_key))
    }

    /// Sign a message with this keypair.
    ///
    /// # Arguments
    /// * `message` - The message to sign
    ///
    /// # Returns
    /// A 64-byte signature
    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        let signature = self.signing_key.sign(message);
        signature.to_bytes()
    }

    /// Verify a signature against a message using this keypair's public key.
    ///
    /// # Arguments
    /// * `message` - The original message
    /// * `signature` - The 64-byte signature to verify
    ///
    /// # Errors
    /// Returns an error if the signature is invalid.
    pub fn verify(&self, message: &[u8], signature: &[u8; 64]) -> Result<(), Ed25519Error> {
        let signature = Signature::from_bytes(signature);
        let verifying_key = self.signing_key.verifying_key();
        verifying_key
            .verify(message, &signature)
            .map_err(|_| Ed25519Error::VerificationFailed)
    }

    /// Get the public key as bytes.
    pub fn public_key_bytes(&self) -> &[u8; 32] {
        &self.public_key
    }

    /// Get the private key as bytes.
    pub fn private_key_bytes(&self) -> &[u8; 32] {
        &self.private_key
    }
}

/// Verify a signature using a public key.
///
/// This is a standalone function for cases where you only have the public key.
///
/// # Arguments
/// * `public_key` - The 32-byte public key
/// * `message` - The original message
/// * `signature` - The 64-byte signature to verify
///
/// # Errors
/// Returns an error if the public key or signature is invalid.
pub fn verify_signature(
    public_key: &[u8; 32],
    message: &[u8],
    signature: &[u8; 64],
) -> Result<(), Ed25519Error> {
    let verifying_key = VerifyingKey::from_bytes(public_key)
        .map_err(|e| Ed25519Error::InvalidKey(e.to_string()))?;
    let signature = Signature::from_bytes(signature);
    verifying_key
        .verify(message, &signature)
        .map_err(|_| Ed25519Error::VerificationFailed)
}

/// Verify a signature from byte slices.
///
/// This is a convenience function that accepts slices instead of arrays.
///
/// # Arguments
/// * `public_key` - A 32-byte slice containing the public key
/// * `message` - The original message
/// * `signature` - A 64-byte slice containing the signature
///
/// # Errors
/// Returns an error if the lengths are incorrect or verification fails.
pub fn verify_signature_slice(
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), Ed25519Error> {
    if public_key.len() != 32 {
        return Err(Ed25519Error::InvalidKey(format!(
            "Public key must be 32 bytes, got {}",
            public_key.len()
        )));
    }
    if signature.len() != 64 {
        return Err(Ed25519Error::InvalidSignature);
    }

    let mut pk = [0u8; 32];
    pk.copy_from_slice(public_key);
    let mut sig = [0u8; 64];
    sig.copy_from_slice(signature);

    verify_signature(&pk, message, &sig)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_generation() {
        let keypair = Ed25519Keypair::generate();
        assert_eq!(keypair.private_key_bytes().len(), 32);
        assert_eq!(keypair.public_key.len(), 32);
    }

    #[test]
    fn test_sign_and_verify() {
        let keypair = Ed25519Keypair::generate();
        let message = b"Hello, TON!";

        let signature = keypair.sign(message);
        assert_eq!(signature.len(), 64);

        assert!(keypair.verify(message, &signature).is_ok());
    }

    #[test]
    fn test_verify_wrong_message() {
        let keypair = Ed25519Keypair::generate();
        let message = b"Hello, TON!";
        let wrong_message = b"Wrong message";

        let signature = keypair.sign(message);

        assert!(keypair.verify(wrong_message, &signature).is_err());
    }

    #[test]
    fn test_verify_wrong_signature() {
        let keypair = Ed25519Keypair::generate();
        let message = b"Hello, TON!";

        let mut signature = keypair.sign(message);
        signature[0] ^= 0xFF; // Corrupt the signature

        assert!(keypair.verify(message, &signature).is_err());
    }

    #[test]
    fn test_from_private_key() {
        let keypair1 = Ed25519Keypair::generate();
        let keypair2 = Ed25519Keypair::from_private_key(*keypair1.private_key_bytes());

        assert_eq!(keypair1.public_key, keypair2.public_key);
    }

    #[test]
    fn test_standalone_verify() {
        let keypair = Ed25519Keypair::generate();
        let message = b"Hello, TON!";
        let signature = keypair.sign(message);

        assert!(verify_signature(&keypair.public_key, message, &signature).is_ok());
    }

    #[test]
    fn test_deterministic_signing() {
        let keypair = Ed25519Keypair::generate();
        let message = b"Hello, TON!";

        let signature1 = keypair.sign(message);
        let signature2 = keypair.sign(message);

        // Ed25519 signatures should be deterministic
        assert_eq!(signature1, signature2);
    }
}
