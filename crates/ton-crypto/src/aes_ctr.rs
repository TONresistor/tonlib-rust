//! AES-CTR encryption implementation for TON.
//!
//! This module provides AES-256 in Counter mode (CTR), which is used
//! in TON ADNL for symmetric encryption of messages.

use aes::cipher::{KeyIvInit, StreamCipher};
use thiserror::Error;

type Aes256Ctr = ctr::Ctr128BE<aes::Aes256>;

/// Errors that can occur during AES-CTR operations.
#[derive(Debug, Error)]
pub enum AesCtrError {
    /// The provided key is invalid.
    #[error("Invalid key: {0}")]
    InvalidKey(String),

    /// The provided IV is invalid.
    #[error("Invalid IV: {0}")]
    InvalidIv(String),
}

/// AES-256-CTR cipher for encryption and decryption.
///
/// In CTR mode, encryption and decryption are the same operation (XOR with keystream).
/// The cipher maintains state, so each call to encrypt/decrypt continues from where
/// the previous call left off.
///
/// # Example
/// ```
/// use ton_crypto::aes_ctr::AesCtrCipher;
///
/// let key = [0u8; 32];
/// let iv = [0u8; 16];
/// let mut cipher = AesCtrCipher::new(key, iv);
///
/// let plaintext = b"Hello, TON!";
/// let ciphertext = cipher.encrypt(plaintext);
///
/// // Reset cipher for decryption
/// let mut cipher2 = AesCtrCipher::new(key, iv);
/// let decrypted = cipher2.decrypt(&ciphertext);
///
/// assert_eq!(plaintext.as_slice(), decrypted.as_slice());
/// ```
pub struct AesCtrCipher {
    /// The 32-byte AES key.
    key: [u8; 32],
    /// The 16-byte initialization vector.
    iv: [u8; 16],
    /// The underlying CTR cipher.
    cipher: Aes256Ctr,
}

impl AesCtrCipher {
    /// Create a new AES-CTR cipher.
    ///
    /// # Arguments
    /// * `key` - A 32-byte key for AES-256
    /// * `iv` - A 16-byte initialization vector (nonce + counter)
    ///
    /// # Returns
    /// A new `AesCtrCipher` ready for encryption/decryption
    pub fn new(key: [u8; 32], iv: [u8; 16]) -> Self {
        let cipher = Aes256Ctr::new(&key.into(), &iv.into());
        Self { key, iv, cipher }
    }

    /// Create a cipher from byte slices.
    ///
    /// # Arguments
    /// * `key` - A 32-byte slice containing the AES key
    /// * `iv` - A 16-byte slice containing the IV
    ///
    /// # Errors
    /// Returns an error if key is not 32 bytes or IV is not 16 bytes.
    pub fn from_slices(key: &[u8], iv: &[u8]) -> Result<Self, AesCtrError> {
        if key.len() != 32 {
            return Err(AesCtrError::InvalidKey(format!(
                "Expected 32 bytes, got {}",
                key.len()
            )));
        }
        if iv.len() != 16 {
            return Err(AesCtrError::InvalidIv(format!(
                "Expected 16 bytes, got {}",
                iv.len()
            )));
        }

        let mut key_arr = [0u8; 32];
        key_arr.copy_from_slice(key);
        let mut iv_arr = [0u8; 16];
        iv_arr.copy_from_slice(iv);

        Ok(Self::new(key_arr, iv_arr))
    }

    /// Encrypt data in place.
    ///
    /// # Arguments
    /// * `data` - The data to encrypt (modified in place)
    pub fn encrypt_in_place(&mut self, data: &mut [u8]) {
        self.cipher.apply_keystream(data);
    }

    /// Encrypt data and return the ciphertext.
    ///
    /// # Arguments
    /// * `data` - The plaintext to encrypt
    ///
    /// # Returns
    /// The encrypted ciphertext
    pub fn encrypt(&mut self, data: &[u8]) -> Vec<u8> {
        let mut output = data.to_vec();
        self.cipher.apply_keystream(&mut output);
        output
    }

    /// Decrypt data in place.
    ///
    /// In CTR mode, decryption is the same as encryption.
    ///
    /// # Arguments
    /// * `data` - The data to decrypt (modified in place)
    pub fn decrypt_in_place(&mut self, data: &mut [u8]) {
        self.cipher.apply_keystream(data);
    }

    /// Decrypt data and return the plaintext.
    ///
    /// In CTR mode, decryption is the same as encryption.
    ///
    /// # Arguments
    /// * `data` - The ciphertext to decrypt
    ///
    /// # Returns
    /// The decrypted plaintext
    pub fn decrypt(&mut self, data: &[u8]) -> Vec<u8> {
        let mut output = data.to_vec();
        self.cipher.apply_keystream(&mut output);
        output
    }

    /// Reset the cipher to its initial state.
    ///
    /// This allows reusing the same key/IV for a new encryption/decryption
    /// operation from the beginning.
    pub fn reset(&mut self) {
        self.cipher = Aes256Ctr::new(&self.key.into(), &self.iv.into());
    }

    /// Get the key.
    pub fn key(&self) -> &[u8; 32] {
        &self.key
    }

    /// Get the IV.
    pub fn iv(&self) -> &[u8; 16] {
        &self.iv
    }
}

impl Clone for AesCtrCipher {
    fn clone(&self) -> Self {
        // Create a fresh cipher with the same key/IV
        // Note: This does NOT preserve the internal counter state
        Self::new(self.key, self.iv)
    }
}

/// Encrypt data with a single function call.
///
/// This is a convenience function for one-shot encryption.
///
/// # Arguments
/// * `key` - A 32-byte AES key
/// * `iv` - A 16-byte IV
/// * `data` - The plaintext to encrypt
///
/// # Returns
/// The encrypted ciphertext
pub fn aes_ctr_encrypt(key: &[u8; 32], iv: &[u8; 16], data: &[u8]) -> Vec<u8> {
    let mut cipher = AesCtrCipher::new(*key, *iv);
    cipher.encrypt(data)
}

/// Decrypt data with a single function call.
///
/// This is a convenience function for one-shot decryption.
///
/// # Arguments
/// * `key` - A 32-byte AES key
/// * `iv` - A 16-byte IV
/// * `data` - The ciphertext to decrypt
///
/// # Returns
/// The decrypted plaintext
pub fn aes_ctr_decrypt(key: &[u8; 32], iv: &[u8; 16], data: &[u8]) -> Vec<u8> {
    let mut cipher = AesCtrCipher::new(*key, *iv);
    cipher.decrypt(data)
}

/// Derive AES key and IV for ADNL encryption from shared secret and message digest.
///
/// This follows the TON official key derivation scheme from `keys/encryptor.cpp`:
/// - AES key = shared_secret[0..16] || digest[16..32]
/// - AES IV  = digest[0..4] || shared_secret[20..32]
///
/// # Arguments
/// * `shared_secret` - 32-byte X25519 shared secret from ECDH
/// * `checksum` - SHA256 digest of the message/data being encrypted
///
/// # Returns
/// Tuple of (32-byte AES key, 16-byte IV)
///
/// # Example
/// ```
/// use ton_crypto::aes_ctr::derive_aes_params_adnl;
///
/// let shared_secret = [0x42u8; 32];
/// let checksum = [0x24u8; 32];
///
/// let (aes_key, iv) = derive_aes_params_adnl(&shared_secret, &checksum);
/// assert_eq!(aes_key.len(), 32);
/// assert_eq!(iv.len(), 16);
/// ```
pub fn derive_aes_params_adnl(shared_secret: &[u8; 32], checksum: &[u8; 32]) -> ([u8; 32], [u8; 16]) {
    let mut key = [0u8; 32];
    let mut iv = [0u8; 16];

    // Key derivation: shared_secret[0..16] || checksum[16..32]
    key[0..16].copy_from_slice(&shared_secret[0..16]);
    key[16..32].copy_from_slice(&checksum[16..32]);

    // IV derivation: checksum[0..4] || shared_secret[20..32]
    iv[0..4].copy_from_slice(&checksum[0..4]);
    iv[4..16].copy_from_slice(&shared_secret[20..32]);

    (key, iv)
}

/// Create an AES-CTR cipher for ADNL using the official TON key derivation.
///
/// # Arguments
/// * `shared_secret` - 32-byte X25519 shared secret from ECDH
/// * `checksum` - SHA256 digest of the data being encrypted
pub fn aes_ctr_cipher_adnl(shared_secret: &[u8; 32], checksum: &[u8; 32]) -> AesCtrCipher {
    let (key, iv) = derive_aes_params_adnl(shared_secret, checksum);
    AesCtrCipher::new(key, iv)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt() {
        let key = [0x42u8; 32];
        let iv = [0x24u8; 16];
        let plaintext = b"Hello, TON Network!";

        let mut encrypt_cipher = AesCtrCipher::new(key, iv);
        let ciphertext = encrypt_cipher.encrypt(plaintext);

        // Ciphertext should be different from plaintext
        assert_ne!(plaintext.as_slice(), ciphertext.as_slice());
        assert_eq!(plaintext.len(), ciphertext.len());

        let mut decrypt_cipher = AesCtrCipher::new(key, iv);
        let decrypted = decrypt_cipher.decrypt(&ciphertext);

        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_encrypt_in_place() {
        let key = [0x42u8; 32];
        let iv = [0x24u8; 16];
        let plaintext = b"Hello, TON!";

        let mut data = plaintext.to_vec();
        let mut cipher = AesCtrCipher::new(key, iv);
        cipher.encrypt_in_place(&mut data);

        // Data should be encrypted
        assert_ne!(plaintext.as_slice(), data.as_slice());

        // Reset and decrypt
        cipher.reset();
        cipher.decrypt_in_place(&mut data);

        assert_eq!(plaintext.as_slice(), data.as_slice());
    }

    #[test]
    fn test_streaming_encryption() {
        let key = [0x42u8; 32];
        let iv = [0x24u8; 16];

        // Encrypt in chunks
        let mut encrypt_cipher = AesCtrCipher::new(key, iv);
        let chunk1 = encrypt_cipher.encrypt(b"Hello, ");
        let chunk2 = encrypt_cipher.encrypt(b"TON!");

        // Decrypt all at once
        let mut decrypt_cipher = AesCtrCipher::new(key, iv);
        let mut combined = chunk1.clone();
        combined.extend_from_slice(&chunk2);
        let decrypted = decrypt_cipher.decrypt(&combined);

        assert_eq!(b"Hello, TON!".as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_standalone_functions() {
        let key = [0x42u8; 32];
        let iv = [0x24u8; 16];
        let plaintext = b"Hello, TON!";

        let ciphertext = aes_ctr_encrypt(&key, &iv, plaintext);
        let decrypted = aes_ctr_decrypt(&key, &iv, &ciphertext);

        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_from_slices_valid() {
        let key = [0x42u8; 32];
        let iv = [0x24u8; 16];

        let cipher = AesCtrCipher::from_slices(&key, &iv);
        assert!(cipher.is_ok());
    }

    #[test]
    fn test_from_slices_invalid_key() {
        let key = [0x42u8; 16]; // Wrong size
        let iv = [0x24u8; 16];

        let result = AesCtrCipher::from_slices(&key, &iv);
        assert!(result.is_err());
    }

    #[test]
    fn test_from_slices_invalid_iv() {
        let key = [0x42u8; 32];
        let iv = [0x24u8; 8]; // Wrong size

        let result = AesCtrCipher::from_slices(&key, &iv);
        assert!(result.is_err());
    }

    #[test]
    fn test_empty_data() {
        let key = [0x42u8; 32];
        let iv = [0x24u8; 16];

        let mut cipher = AesCtrCipher::new(key, iv);
        let ciphertext = cipher.encrypt(b"");

        assert!(ciphertext.is_empty());
    }

    #[test]
    fn test_ctr_symmetry() {
        // In CTR mode, encrypt(encrypt(x)) == x when using same key/IV
        let key = [0x42u8; 32];
        let iv = [0x24u8; 16];
        let plaintext = b"Hello, TON!";

        let encrypted = aes_ctr_encrypt(&key, &iv, plaintext);
        let double_encrypted = aes_ctr_encrypt(&key, &iv, &encrypted);

        // Due to CTR mode properties, double encryption returns original
        assert_eq!(plaintext.as_slice(), double_encrypted.as_slice());
    }
}

#[cfg(test)]
mod python_compat_tests {
    use super::*;
    
    #[test]
    fn test_aes_ctr_matches_python_cryptography() {
        // Same key/iv as Python test
        let key: [u8; 32] = core::array::from_fn(|i| 0x20 + i as u8);
        let iv: [u8; 16] = core::array::from_fn(|i| 0x50 + i as u8);
        
        let mut cipher = AesCtrCipher::new(key, iv);
        
        // Encrypt zeros to get keystream
        let keystream = cipher.encrypt(&[0u8; 16]);
        
        // Expected from Python cryptography library
        let expected_keystream = [
            0x44, 0xab, 0x3a, 0xd8, 0x52, 0xf5, 0x57, 0x29,
            0x90, 0x8b, 0xb4, 0xf3, 0x77, 0xf6, 0x39, 0xfb
        ];
        
        println!("Key: {:02x?}", &key[..]);
        println!("IV:  {:02x?}", &iv[..]);
        println!("Rust keystream:   {:02x?}", &keystream[..]);
        println!("Python keystream: {:02x?}", &expected_keystream[..]);
        
        assert_eq!(&keystream[..], &expected_keystream[..], "Keystream must match Python");
    }
    
    #[test]
    fn test_aes_ctr_encrypt_matches_python() {
        let key: [u8; 32] = core::array::from_fn(|i| 0x20 + i as u8);
        let iv: [u8; 16] = core::array::from_fn(|i| 0x50 + i as u8);
        
        let mut cipher = AesCtrCipher::new(key, iv);
        
        // Same data as Python test
        let mut data = vec![0x4c, 0x00, 0x00, 0x00];
        data.extend(0u8..32u8);
        data.extend([0x4d, 0x08, 0x2b, 0x9a]);
        
        let encrypted = cipher.encrypt(&data);
        
        // Expected from Python
        let expected = hex_to_bytes("08ab3ad852f4552a948eb2f47fff33f030c71cccccb15575dd3811185f81528d800d3a1fff928a49");
        
        println!("Data:      {:02x?}", &data[..20]);
        println!("Rust enc:  {:02x?}", &encrypted[..20]);
        println!("Python enc:{:02x?}", &expected[..20]);
        
        assert_eq!(encrypted, expected, "Encryption must match Python");
    }
    
    fn hex_to_bytes(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i+2], 16).unwrap())
            .collect()
    }
}
