//! X25519 ECDH implementation for TON.
//!
//! This module provides X25519 Elliptic Curve Diffie-Hellman key exchange,
//! which is used in TON for establishing shared secrets in ADNL connections.
//!
//! # Security Considerations
//!
//! When performing ECDH key exchange, always use [`X25519Keypair::ecdh_checked`]
//! instead of [`X25519Keypair::ecdh`] to prevent weak key attacks. The checked
//! version validates that the shared secret is not all zeros, which would indicate
//! a weak or malicious public key.
//!
//! # Example
//!
//! ```
//! use ton_crypto::x25519::X25519Keypair;
//!
//! let alice = X25519Keypair::generate();
//! let bob = X25519Keypair::generate();
//!
//! // RECOMMENDED: Use checked ECDH to detect weak keys
//! let shared = alice.ecdh_checked(&bob.public_key)
//!     .expect("Invalid public key detected");
//! ```

use curve25519_dalek::edwards::CompressedEdwardsY;
use rand::rngs::OsRng;
use sha2::{Digest, Sha512};
use thiserror::Error;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Errors that can occur during X25519 operations.
#[derive(Debug, Error)]
pub enum X25519Error {
    /// The provided key bytes are invalid.
    #[error("Invalid key bytes: {0}")]
    InvalidKey(String),

    /// The computed shared secret is all zeros (weak key detected).
    ///
    /// This indicates either a malicious public key or a low-order point.
    /// Such keys should be rejected to prevent security vulnerabilities.
    #[error("Computed shared secret is all zeros - weak key attack detected")]
    WeakKey,
}

/// An X25519 keypair for ECDH key exchange.
///
/// The keypair consists of a 32-byte private key and a 32-byte public key.
/// Used to establish shared secrets with remote peers.
///
/// # Security
///
/// This struct implements `Zeroize` and `ZeroizeOnDrop` to securely erase
/// the private key from memory when dropped. This follows the official TON
/// security guidelines for key material handling.
///
/// # Example
/// ```
/// use ton_crypto::x25519::X25519Keypair;
///
/// // Alice generates her keypair
/// let alice = X25519Keypair::generate();
///
/// // Bob generates his keypair
/// let bob = X25519Keypair::generate();
///
/// // Both compute the same shared secret
/// let alice_shared = alice.ecdh(&bob.public_key);
/// let bob_shared = bob.ecdh(&alice.public_key);
///
/// assert_eq!(alice_shared, bob_shared);
/// ```
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct X25519Keypair {
    /// The 32-byte private key (securely zeroed on drop).
    pub private_key: [u8; 32],
    /// The 32-byte public key.
    pub public_key: [u8; 32],
}

impl X25519Keypair {
    /// Generate a new random X25519 keypair.
    ///
    /// Uses the operating system's cryptographically secure random number generator.
    pub fn generate() -> Self {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);

        Self {
            private_key: secret.to_bytes(),
            public_key: public.to_bytes(),
        }
    }

    /// Create a keypair from a 32-byte private key.
    ///
    /// # Arguments
    /// * `private_key` - The 32-byte private key
    ///
    /// # Returns
    /// A new `X25519Keypair` with the derived public key
    pub fn from_private_key(private_key: [u8; 32]) -> Self {
        let secret = StaticSecret::from(private_key);
        let public = PublicKey::from(&secret);

        Self {
            private_key,
            public_key: public.to_bytes(),
        }
    }

    /// Create a keypair from a byte slice.
    ///
    /// # Arguments
    /// * `bytes` - A 32-byte slice containing the private key
    ///
    /// # Errors
    /// Returns an error if the slice is not exactly 32 bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, X25519Error> {
        if bytes.len() != 32 {
            return Err(X25519Error::InvalidKey(format!(
                "Expected 32 bytes, got {}",
                bytes.len()
            )));
        }
        let mut private_key = [0u8; 32];
        private_key.copy_from_slice(bytes);
        Ok(Self::from_private_key(private_key))
    }

    /// Perform ECDH key exchange to compute a shared secret (unchecked).
    ///
    /// # Arguments
    /// * `their_public_key` - The other party's 32-byte public key
    ///
    /// # Returns
    /// A 32-byte shared secret
    ///
    /// # Security Warning
    ///
    /// **Prefer using [`ecdh_checked`](Self::ecdh_checked) instead!**
    ///
    /// This function does not validate the resulting shared secret.
    /// A malicious peer could send a low-order point that produces an
    /// all-zeros shared secret, compromising security.
    ///
    /// The raw shared secret should typically be passed through a KDF
    /// before use as an encryption key.
    pub fn ecdh(&self, their_public_key: &[u8; 32]) -> [u8; 32] {
        let secret = StaticSecret::from(self.private_key);
        let their_public = PublicKey::from(*their_public_key);
        secret.diffie_hellman(&their_public).to_bytes()
    }

    /// Perform ECDH key exchange with weak key validation.
    ///
    /// This is the **recommended** method for ECDH key exchange.
    /// It checks for weak keys that would result in an all-zero
    /// shared secret, preventing potential security vulnerabilities.
    ///
    /// # Arguments
    /// * `their_public_key` - The other party's 32-byte public key
    ///
    /// # Errors
    /// Returns [`X25519Error::WeakKey`] if the shared secret would be all zeros,
    /// indicating a malicious or invalid public key.
    ///
    /// # Example
    /// ```
    /// use ton_crypto::x25519::X25519Keypair;
    ///
    /// let my_keypair = X25519Keypair::generate();
    /// let their_public = [0u8; 32]; // Some public key
    ///
    /// match my_keypair.ecdh_checked(&their_public) {
    ///     Ok(shared_secret) => println!("Shared secret computed"),
    ///     Err(e) => println!("Weak key detected: {}", e),
    /// }
    /// ```
    pub fn ecdh_checked(&self, their_public_key: &[u8; 32]) -> Result<[u8; 32], X25519Error> {
        let shared = self.ecdh(their_public_key);
        if shared.iter().all(|&b| b == 0) {
            return Err(X25519Error::WeakKey);
        }
        Ok(shared)
    }

    /// Alias for [`ecdh_checked`](Self::ecdh_checked).
    ///
    /// This is the safe version of ECDH that validates against weak keys.
    #[inline]
    pub fn ecdh_safe(&self, their_public_key: &[u8; 32]) -> Result<[u8; 32], X25519Error> {
        self.ecdh_checked(their_public_key)
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

/// Perform a single ECDH operation.
///
/// This is a convenience function for when you already have raw keys
/// and don't need to create a keypair object.
///
/// # Arguments
/// * `private_key` - Your 32-byte private key
/// * `their_public_key` - Their 32-byte public key
///
/// # Returns
/// A 32-byte shared secret
pub fn ecdh(private_key: &[u8; 32], their_public_key: &[u8; 32]) -> [u8; 32] {
    let secret = StaticSecret::from(*private_key);
    let public = PublicKey::from(*their_public_key);
    secret.diffie_hellman(&public).to_bytes()
}

/// Derive a public key from a private key.
///
/// # Arguments
/// * `private_key` - A 32-byte private key
///
/// # Returns
/// The corresponding 32-byte public key
pub fn derive_public_key(private_key: &[u8; 32]) -> [u8; 32] {
    let secret = StaticSecret::from(*private_key);
    let public = PublicKey::from(&secret);
    public.to_bytes()
}

/// Convert an Ed25519 private key (seed) to an X25519 private key.
///
/// This follows the official TON ADNL implementation:
/// 1. Hash the Ed25519 seed with SHA512
/// 2. Take the first 32 bytes
/// 3. Apply clamping (required for X25519 scalar multiplication)
///
/// The clamping process:
/// - Clear bits 0, 1, 2 (ensures divisibility by 8)
/// - Clear bit 255 (ensures the scalar is less than the group order)
/// - Set bit 254 (ensures constant-time ladder)
///
/// # Arguments
/// * `ed25519_private_key` - The 32-byte Ed25519 seed
///
/// # Returns
/// The 32-byte X25519 private key
pub fn ed25519_to_x25519_private(ed25519_private_key: &[u8; 32]) -> [u8; 32] {
    // SHA512 of the Ed25519 seed
    let mut hasher = Sha512::new();
    hasher.update(ed25519_private_key);
    let hash = hasher.finalize();

    // Take first 32 bytes
    let mut x25519_private = [0u8; 32];
    x25519_private.copy_from_slice(&hash[..32]);

    // Clamp according to RFC 7748 / official TON
    x25519_private[0] &= 248;   // Clear bits 0, 1, 2
    x25519_private[31] &= 127;  // Clear bit 255
    x25519_private[31] |= 64;   // Set bit 254

    x25519_private
}

/// Convert an Ed25519 public key to an X25519 public key.
///
/// This converts a point on the Edwards curve to the equivalent point
/// on the Montgomery curve using the birational map:
/// u = (1 + y) / (1 - y) mod p
///
/// This matches the official TON ADNL implementation for ECDH key exchange.
///
/// # Arguments
/// * `ed25519_public_key` - The 32-byte Ed25519 public key
///
/// # Returns
/// The 32-byte X25519 public key, or an error if the input is invalid
pub fn ed25519_to_x25519_public(ed25519_public_key: &[u8; 32]) -> Result<[u8; 32], X25519Error> {
    // Decompress the Edwards point
    let compressed = CompressedEdwardsY::from_slice(ed25519_public_key)
        .map_err(|_| X25519Error::InvalidKey("Invalid Ed25519 public key length".into()))?;

    let edwards_point = compressed
        .decompress()
        .ok_or_else(|| X25519Error::InvalidKey("Failed to decompress Ed25519 public key".into()))?;

    // Convert to Montgomery form
    let montgomery_point = edwards_point.to_montgomery();

    Ok(montgomery_point.to_bytes())
}

/// Perform ECDH key exchange using Ed25519 keys (as used in TON ADNL).
///
/// This function converts Ed25519 keys to X25519 keys internally and then
/// performs the standard X25519 ECDH operation.
///
/// This is the correct way to do ECDH in TON ADNL, matching the official implementation.
///
/// # Arguments
/// * `my_ed25519_private` - Your Ed25519 private key (seed)
/// * `their_ed25519_public` - Their Ed25519 public key
///
/// # Returns
/// The 32-byte shared secret, or an error if the public key is invalid
///
/// # Example
/// ```
/// use ton_crypto::x25519::ecdh_ed25519;
/// use ton_crypto::ed25519::Ed25519Keypair;
///
/// let alice = Ed25519Keypair::generate();
/// let bob = Ed25519Keypair::generate();
///
/// // Both derive the same shared secret
/// let alice_shared = ecdh_ed25519(alice.private_key_bytes(), &bob.public_key).unwrap();
/// let bob_shared = ecdh_ed25519(bob.private_key_bytes(), &alice.public_key).unwrap();
///
/// assert_eq!(alice_shared, bob_shared);
/// ```
pub fn ecdh_ed25519(
    my_ed25519_private: &[u8; 32],
    their_ed25519_public: &[u8; 32],
) -> Result<[u8; 32], X25519Error> {
    // Convert Ed25519 keys to X25519
    let x25519_private = ed25519_to_x25519_private(my_ed25519_private);
    let x25519_public = ed25519_to_x25519_public(their_ed25519_public)?;

    // Perform standard X25519 ECDH
    let shared = ecdh(&x25519_private, &x25519_public);

    // Check for weak key
    if shared.iter().all(|&b| b == 0) {
        return Err(X25519Error::WeakKey);
    }

    Ok(shared)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_generation() {
        let keypair = X25519Keypair::generate();
        assert_eq!(keypair.private_key.len(), 32);
        assert_eq!(keypair.public_key.len(), 32);
    }

    #[test]
    fn test_ecdh_key_agreement() {
        let alice = X25519Keypair::generate();
        let bob = X25519Keypair::generate();

        let alice_shared = alice.ecdh(&bob.public_key);
        let bob_shared = bob.ecdh(&alice.public_key);

        assert_eq!(alice_shared, bob_shared);
    }

    #[test]
    fn test_from_private_key() {
        let keypair1 = X25519Keypair::generate();
        let keypair2 = X25519Keypair::from_private_key(keypair1.private_key);

        assert_eq!(keypair1.public_key, keypair2.public_key);
    }

    #[test]
    fn test_standalone_ecdh() {
        let alice = X25519Keypair::generate();
        let bob = X25519Keypair::generate();

        let shared1 = ecdh(&alice.private_key, &bob.public_key);
        let shared2 = alice.ecdh(&bob.public_key);

        assert_eq!(shared1, shared2);
    }

    #[test]
    fn test_derive_public_key() {
        let keypair = X25519Keypair::generate();
        let derived = derive_public_key(&keypair.private_key);

        assert_eq!(keypair.public_key, derived);
    }

    #[test]
    fn test_different_keypairs_different_shared_secrets() {
        let alice = X25519Keypair::generate();
        let bob = X25519Keypair::generate();
        let charlie = X25519Keypair::generate();

        let alice_bob = alice.ecdh(&bob.public_key);
        let alice_charlie = alice.ecdh(&charlie.public_key);

        assert_ne!(alice_bob, alice_charlie);
    }

    #[test]
    fn test_from_bytes_valid() {
        let keypair = X25519Keypair::generate();
        let restored = X25519Keypair::from_bytes(&keypair.private_key).unwrap();

        assert_eq!(keypair.public_key, restored.public_key);
    }

    #[test]
    fn test_from_bytes_invalid_length() {
        let short_key = [0u8; 16];
        let result = X25519Keypair::from_bytes(&short_key);

        assert!(result.is_err());
    }

    #[test]
    fn test_weak_key_detection() {
        let keypair = X25519Keypair::generate();

        // All-zeros public key is a weak key (low-order point)
        let weak_key = [0u8; 32];
        let result = keypair.ecdh_checked(&weak_key);

        // Should detect weak key and return error
        assert!(result.is_err());
        assert!(matches!(result, Err(X25519Error::WeakKey)));
    }

    #[test]
    fn test_ecdh_safe_alias() {
        let alice = X25519Keypair::generate();
        let bob = X25519Keypair::generate();

        // ecdh_safe should work the same as ecdh_checked
        let safe_result = alice.ecdh_safe(&bob.public_key);
        let checked_result = alice.ecdh_checked(&bob.public_key);

        assert!(safe_result.is_ok());
        assert_eq!(safe_result.unwrap(), checked_result.unwrap());
    }

    #[test]
    fn test_ed25519_to_x25519_private_clamping() {
        let ed25519_key = [0x42u8; 32];
        let x25519_key = ed25519_to_x25519_private(&ed25519_key);

        // Check clamping was applied correctly
        assert_eq!(x25519_key[0] & 7, 0); // Bottom 3 bits should be 0
        assert_eq!(x25519_key[31] & 128, 0); // Bit 255 should be 0
        assert_eq!(x25519_key[31] & 64, 64); // Bit 254 should be 1
    }

    #[test]
    fn test_ed25519_to_x25519_public_valid() {
        use crate::ed25519::Ed25519Keypair;

        let ed25519 = Ed25519Keypair::generate();
        let result = ed25519_to_x25519_public(&ed25519.public_key);

        assert!(result.is_ok());
        let x25519_public = result.unwrap();
        assert_eq!(x25519_public.len(), 32);
    }

    #[test]
    fn test_ecdh_ed25519_symmetric() {
        use crate::ed25519::Ed25519Keypair;

        let alice = Ed25519Keypair::generate();
        let bob = Ed25519Keypair::generate();

        // Both should derive the same shared secret
        let alice_shared = ecdh_ed25519(alice.private_key_bytes(), &bob.public_key).unwrap();
        let bob_shared = ecdh_ed25519(bob.private_key_bytes(), &alice.public_key).unwrap();

        assert_eq!(alice_shared, bob_shared);
    }

    #[test]
    fn test_ecdh_ed25519_different_peers_different_secrets() {
        use crate::ed25519::Ed25519Keypair;

        let alice = Ed25519Keypair::generate();
        let bob = Ed25519Keypair::generate();
        let charlie = Ed25519Keypair::generate();

        let alice_bob = ecdh_ed25519(alice.private_key_bytes(), &bob.public_key).unwrap();
        let alice_charlie = ecdh_ed25519(alice.private_key_bytes(), &charlie.public_key).unwrap();

        assert_ne!(alice_bob, alice_charlie);
    }

    #[test]
    fn test_ed25519_to_x25519_deterministic() {
        let ed25519_key = [0x55u8; 32];

        let x25519_key1 = ed25519_to_x25519_private(&ed25519_key);
        let x25519_key2 = ed25519_to_x25519_private(&ed25519_key);

        assert_eq!(x25519_key1, x25519_key2);
    }
}

#[cfg(test)]
mod tonutils_go_compat_tests {
    use super::*;

    /// Test vector from tonutils-go crypto_test.go
    /// This verifies our ECDH produces identical results to the Go implementation
    #[test]
    fn test_shared_key_matches_tonutils_go() {
        // Test data from tonutils-go
        let our_seed: [u8; 32] = [
            175, 46, 138, 194, 124, 100, 226, 85,
            88, 44, 196, 159, 130, 167, 223, 23,
            125, 231, 145, 177, 104, 171, 189, 252,
            16, 143, 108, 237, 99, 32, 104, 10,
        ];
        
        let server_pubkey: [u8; 32] = [
            159, 133, 67, 157, 32, 148, 185, 42,
            99, 156, 44, 148, 147, 215, 183, 64,
            227, 157, 234, 141, 8, 181, 37, 152,
            109, 57, 214, 221, 105, 231, 243, 9,
        ];
        
        let expected_shared: [u8; 32] = [
            220, 183, 46, 193, 213, 106, 149, 6,
            197, 7, 75, 228, 108, 247, 216, 126,
            194, 59, 250, 51, 191, 19, 17, 221,
            189, 86, 228, 159, 226, 223, 135, 119,
        ];
        
        // Compute shared secret using our implementation
        let shared = ecdh_ed25519(&our_seed, &server_pubkey)
            .expect("ECDH should succeed");
        
        println!("Our shared:      {:?}", shared);
        println!("Expected shared: {:?}", expected_shared);
        
        assert_eq!(shared, expected_shared, "ECDH must match tonutils-go");
    }
}
