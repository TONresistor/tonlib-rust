//! Key Derivation Functions (KDF) for TON.
//!
//! This module provides PBKDF2 and HMAC implementations using SHA256 and SHA512.
//! These are commonly used for:
//!
//! - **PBKDF2**: Deriving cryptographic keys from passwords
//! - **HMAC**: Message authentication codes for data integrity
//!
//! # Example: Deriving a Key from Password
//!
//! ```
//! use ton_crypto::kdf::pbkdf2_sha256;
//!
//! let password = b"my_secure_password";
//! let salt = b"random_salt_value";
//! let iterations = 100_000;
//! let mut derived_key = [0u8; 32];
//!
//! pbkdf2_sha256(password, salt, iterations, &mut derived_key);
//! ```
//!
//! # Example: Computing HMAC
//!
//! ```
//! use ton_crypto::kdf::hmac_sha256;
//!
//! let key = b"secret_key";
//! let message = b"data to authenticate";
//! let mac = hmac_sha256(key, message);
//! ```

use hmac::{Hmac, Mac};
use sha2::{Sha256, Sha512};

type HmacSha256 = Hmac<Sha256>;
type HmacSha512 = Hmac<Sha512>;

/// Derive a key using PBKDF2 with SHA256.
///
/// PBKDF2 (Password-Based Key Derivation Function 2) is used to derive
/// cryptographic keys from passwords. It applies a pseudorandom function
/// (HMAC-SHA256) iteratively to make brute-force attacks more expensive.
///
/// # Arguments
/// * `password` - The password to derive the key from
/// * `salt` - A random salt to prevent rainbow table attacks
/// * `iterations` - Number of iterations (higher = slower but more secure)
/// * `output` - Buffer to write the derived key into
///
/// # Example
/// ```
/// use ton_crypto::kdf::pbkdf2_sha256;
///
/// let mut key = [0u8; 32];
/// pbkdf2_sha256(b"password", b"salt", 10000, &mut key);
/// assert_ne!(key, [0u8; 32]);
/// ```
pub fn pbkdf2_sha256(password: &[u8], salt: &[u8], iterations: u32, output: &mut [u8]) {
    pbkdf2::pbkdf2::<HmacSha256>(password, salt, iterations, output)
        .expect("HMAC can be initialized with any key length");
}

/// Derive a key using PBKDF2 with SHA512.
///
/// Similar to `pbkdf2_sha256` but uses SHA512 as the underlying hash function,
/// which may provide better security margins for longer derived keys.
///
/// # Arguments
/// * `password` - The password to derive the key from
/// * `salt` - A random salt to prevent rainbow table attacks
/// * `iterations` - Number of iterations (higher = slower but more secure)
/// * `output` - Buffer to write the derived key into
///
/// # Example
/// ```
/// use ton_crypto::kdf::pbkdf2_sha512;
///
/// let mut key = [0u8; 64];
/// pbkdf2_sha512(b"password", b"salt", 10000, &mut key);
/// assert_ne!(key, [0u8; 64]);
/// ```
pub fn pbkdf2_sha512(password: &[u8], salt: &[u8], iterations: u32, output: &mut [u8]) {
    pbkdf2::pbkdf2::<HmacSha512>(password, salt, iterations, output)
        .expect("HMAC can be initialized with any key length");
}

/// Compute HMAC-SHA256 of the given data.
///
/// HMAC (Hash-based Message Authentication Code) provides both data integrity
/// and authenticity verification. It uses a secret key along with a hash
/// function to produce a fixed-size authentication tag.
///
/// # Arguments
/// * `key` - The secret key for HMAC
/// * `data` - The data to authenticate
///
/// # Returns
/// A 32-byte HMAC-SHA256 tag
///
/// # Example
/// ```
/// use ton_crypto::kdf::hmac_sha256;
///
/// let mac = hmac_sha256(b"key", b"message");
/// assert_eq!(mac.len(), 32);
/// ```
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac =
        HmacSha256::new_from_slice(key).expect("HMAC can be initialized with any key length");
    mac.update(data);
    let result = mac.finalize();
    let mut output = [0u8; 32];
    output.copy_from_slice(&result.into_bytes());
    output
}

/// Compute HMAC-SHA512 of the given data.
///
/// Similar to `hmac_sha256` but uses SHA512 as the underlying hash function,
/// producing a 64-byte authentication tag.
///
/// # Arguments
/// * `key` - The secret key for HMAC
/// * `data` - The data to authenticate
///
/// # Returns
/// A 64-byte HMAC-SHA512 tag
///
/// # Example
/// ```
/// use ton_crypto::kdf::hmac_sha512;
///
/// let mac = hmac_sha512(b"key", b"message");
/// assert_eq!(mac.len(), 64);
/// ```
pub fn hmac_sha512(key: &[u8], data: &[u8]) -> [u8; 64] {
    let mut mac =
        HmacSha512::new_from_slice(key).expect("HMAC can be initialized with any key length");
    mac.update(data);
    let result = mac.finalize();
    let mut output = [0u8; 64];
    output.copy_from_slice(&result.into_bytes());
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pbkdf2_sha256_basic() {
        let mut output = [0u8; 32];
        pbkdf2_sha256(b"password", b"salt", 1, &mut output);

        // Verify output is not all zeros
        assert_ne!(output, [0u8; 32]);
    }

    #[test]
    fn test_pbkdf2_sha256_deterministic() {
        let mut output1 = [0u8; 32];
        let mut output2 = [0u8; 32];

        pbkdf2_sha256(b"password", b"salt", 1000, &mut output1);
        pbkdf2_sha256(b"password", b"salt", 1000, &mut output2);

        assert_eq!(output1, output2);
    }

    #[test]
    fn test_pbkdf2_sha256_different_passwords() {
        let mut output1 = [0u8; 32];
        let mut output2 = [0u8; 32];

        pbkdf2_sha256(b"password1", b"salt", 1000, &mut output1);
        pbkdf2_sha256(b"password2", b"salt", 1000, &mut output2);

        assert_ne!(output1, output2);
    }

    #[test]
    fn test_pbkdf2_sha256_different_salts() {
        let mut output1 = [0u8; 32];
        let mut output2 = [0u8; 32];

        pbkdf2_sha256(b"password", b"salt1", 1000, &mut output1);
        pbkdf2_sha256(b"password", b"salt2", 1000, &mut output2);

        assert_ne!(output1, output2);
    }

    #[test]
    fn test_pbkdf2_sha256_rfc6070_vector() {
        // RFC 6070 test vector for PBKDF2-HMAC-SHA256
        // Input: P = "password", S = "salt", c = 1, dkLen = 32
        let mut output = [0u8; 32];
        pbkdf2_sha256(b"password", b"salt", 1, &mut output);

        // Expected output from RFC 6070 / known test vectors
        let expected = [
            0x12, 0x0f, 0xb6, 0xcf, 0xfc, 0xf8, 0xb3, 0x2c, 0x43, 0xe7, 0x22, 0x52, 0x56, 0xc4,
            0xf8, 0x37, 0xa8, 0x65, 0x48, 0xc9, 0x2c, 0xcc, 0x35, 0x48, 0x08, 0x05, 0x98, 0x7c,
            0xb7, 0x0b, 0xe1, 0x7b,
        ];
        assert_eq!(output, expected);
    }

    #[test]
    fn test_pbkdf2_sha512_basic() {
        let mut output = [0u8; 64];
        pbkdf2_sha512(b"password", b"salt", 1, &mut output);

        assert_ne!(output, [0u8; 64]);
    }

    #[test]
    fn test_pbkdf2_sha512_deterministic() {
        let mut output1 = [0u8; 64];
        let mut output2 = [0u8; 64];

        pbkdf2_sha512(b"password", b"salt", 1000, &mut output1);
        pbkdf2_sha512(b"password", b"salt", 1000, &mut output2);

        assert_eq!(output1, output2);
    }

    #[test]
    fn test_pbkdf2_sha512_variable_output_length() {
        let mut output_short = [0u8; 16];
        let mut output_long = [0u8; 128];

        pbkdf2_sha512(b"password", b"salt", 1000, &mut output_short);
        pbkdf2_sha512(b"password", b"salt", 1000, &mut output_long);

        // First 16 bytes should match
        assert_eq!(output_short, output_long[..16]);
    }

    #[test]
    fn test_hmac_sha256_basic() {
        let mac = hmac_sha256(b"key", b"message");
        assert_eq!(mac.len(), 32);
        assert_ne!(mac, [0u8; 32]);
    }

    #[test]
    fn test_hmac_sha256_deterministic() {
        let mac1 = hmac_sha256(b"key", b"message");
        let mac2 = hmac_sha256(b"key", b"message");
        assert_eq!(mac1, mac2);
    }

    #[test]
    fn test_hmac_sha256_different_keys() {
        let mac1 = hmac_sha256(b"key1", b"message");
        let mac2 = hmac_sha256(b"key2", b"message");
        assert_ne!(mac1, mac2);
    }

    #[test]
    fn test_hmac_sha256_different_messages() {
        let mac1 = hmac_sha256(b"key", b"message1");
        let mac2 = hmac_sha256(b"key", b"message2");
        assert_ne!(mac1, mac2);
    }

    #[test]
    fn test_hmac_sha256_rfc4231_vector() {
        // RFC 4231 Test Case 1 for HMAC-SHA256
        // Key = 0x0b repeated 20 times
        // Data = "Hi There"
        let key = [0x0bu8; 20];
        let data = b"Hi There";
        let mac = hmac_sha256(&key, data);

        let expected = [
            0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53, 0x5c, 0xa8, 0xaf, 0xce, 0xaf, 0x0b,
            0xf1, 0x2b, 0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7, 0x26, 0xe9, 0x37, 0x6c,
            0x2e, 0x32, 0xcf, 0xf7,
        ];
        assert_eq!(mac, expected);
    }

    #[test]
    fn test_hmac_sha512_basic() {
        let mac = hmac_sha512(b"key", b"message");
        assert_eq!(mac.len(), 64);
        assert_ne!(mac, [0u8; 64]);
    }

    #[test]
    fn test_hmac_sha512_deterministic() {
        let mac1 = hmac_sha512(b"key", b"message");
        let mac2 = hmac_sha512(b"key", b"message");
        assert_eq!(mac1, mac2);
    }

    #[test]
    fn test_hmac_sha512_different_keys() {
        let mac1 = hmac_sha512(b"key1", b"message");
        let mac2 = hmac_sha512(b"key2", b"message");
        assert_ne!(mac1, mac2);
    }

    #[test]
    fn test_hmac_sha512_rfc4231_vector() {
        // RFC 4231 Test Case 1 for HMAC-SHA512
        // Key = 0x0b repeated 20 times
        // Data = "Hi There"
        let key = [0x0bu8; 20];
        let data = b"Hi There";
        let mac = hmac_sha512(&key, data);

        let expected = [
            0x87, 0xaa, 0x7c, 0xde, 0xa5, 0xef, 0x61, 0x9d, 0x4f, 0xf0, 0xb4, 0x24, 0x1a, 0x1d,
            0x6c, 0xb0, 0x23, 0x79, 0xf4, 0xe2, 0xce, 0x4e, 0xc2, 0x78, 0x7a, 0xd0, 0xb3, 0x05,
            0x45, 0xe1, 0x7c, 0xde, 0xda, 0xa8, 0x33, 0xb7, 0xd6, 0xb8, 0xa7, 0x02, 0x03, 0x8b,
            0x27, 0x4e, 0xae, 0xa3, 0xf4, 0xe4, 0xbe, 0x9d, 0x91, 0x4e, 0xeb, 0x61, 0xf1, 0x70,
            0x2e, 0x69, 0x6c, 0x20, 0x3a, 0x12, 0x68, 0x54,
        ];
        assert_eq!(mac, expected);
    }

    #[test]
    fn test_hmac_sha256_empty_key() {
        // HMAC should work with empty key
        let mac = hmac_sha256(b"", b"message");
        assert_eq!(mac.len(), 32);
    }

    #[test]
    fn test_hmac_sha256_empty_message() {
        // HMAC should work with empty message
        let mac = hmac_sha256(b"key", b"");
        assert_eq!(mac.len(), 32);
    }

    #[test]
    fn test_hmac_sha512_long_key() {
        // HMAC should work with keys longer than block size
        let long_key = [0xaau8; 256];
        let mac = hmac_sha512(&long_key, b"message");
        assert_eq!(mac.len(), 64);
    }
}
