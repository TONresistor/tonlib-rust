//! SHA256 hashing implementation for TON.
//!
//! This module provides SHA256 hashing functionality used throughout
//! the TON protocol for message digests, key IDs, and various checksums.

use sha2::{Digest, Sha256};

/// Compute SHA256 hash of the input data.
///
/// # Arguments
/// * `data` - The input bytes to hash
///
/// # Returns
/// A 32-byte array containing the SHA256 digest
///
/// # Example
/// ```
/// use ton_crypto::sha256::sha256;
///
/// let hash = sha256(b"Hello, TON!");
/// assert_eq!(hash.len(), 32);
/// ```
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut output = [0u8; 32];
    output.copy_from_slice(&result);
    output
}

/// Compute SHA256 hash of multiple data slices.
///
/// This is useful when you need to hash concatenated data without
/// actually concatenating it first.
///
/// # Arguments
/// * `parts` - Slice of byte slices to hash in sequence
///
/// # Returns
/// A 32-byte array containing the SHA256 digest
///
/// # Example
/// ```
/// use ton_crypto::sha256::sha256_multi;
///
/// let hash = sha256_multi(&[b"Hello, ", b"TON!"]);
/// ```
pub fn sha256_multi(parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part);
    }
    let result = hasher.finalize();
    let mut output = [0u8; 32];
    output.copy_from_slice(&result);
    output
}

/// A streaming SHA256 hasher that can be updated incrementally.
///
/// Useful when hashing large amounts of data or when data arrives
/// in chunks.
///
/// # Example
/// ```
/// use ton_crypto::sha256::Sha256Hasher;
///
/// let mut hasher = Sha256Hasher::new();
/// hasher.update(b"Hello, ");
/// hasher.update(b"TON!");
/// let hash = hasher.finalize();
/// ```
pub struct Sha256Hasher {
    inner: Sha256,
}

impl Sha256Hasher {
    /// Create a new SHA256 hasher.
    pub fn new() -> Self {
        Self {
            inner: Sha256::new(),
        }
    }

    /// Update the hasher with additional data.
    pub fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    /// Finalize the hash and return the digest.
    ///
    /// This consumes the hasher.
    pub fn finalize(self) -> [u8; 32] {
        let result = self.inner.finalize();
        let mut output = [0u8; 32];
        output.copy_from_slice(&result);
        output
    }

    /// Reset the hasher to its initial state.
    pub fn reset(&mut self) {
        self.inner = Sha256::new();
    }
}

impl Default for Sha256Hasher {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256_empty() {
        let hash = sha256(b"");
        // SHA256 of empty string
        let expected = [
            0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f,
            0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b,
            0x78, 0x52, 0xb8, 0x55,
        ];
        assert_eq!(hash, expected);
    }

    #[test]
    fn test_sha256_hello() {
        let hash = sha256(b"hello");
        // SHA256 of "hello"
        let expected = [
            0x2c, 0xf2, 0x4d, 0xba, 0x5f, 0xb0, 0xa3, 0x0e, 0x26, 0xe8, 0x3b, 0x2a, 0xc5, 0xb9,
            0xe2, 0x9e, 0x1b, 0x16, 0x1e, 0x5c, 0x1f, 0xa7, 0x42, 0x5e, 0x73, 0x04, 0x33, 0x62,
            0x93, 0x8b, 0x98, 0x24,
        ];
        assert_eq!(hash, expected);
    }

    #[test]
    fn test_sha256_multi() {
        let hash1 = sha256(b"HelloWorld");
        let hash2 = sha256_multi(&[b"Hello", b"World"]);
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_sha256_hasher_streaming() {
        let mut hasher = Sha256Hasher::new();
        hasher.update(b"Hello");
        hasher.update(b"World");
        let hash1 = hasher.finalize();

        let hash2 = sha256(b"HelloWorld");
        assert_eq!(hash1, hash2);
    }
}
