//! TON mnemonic generation and key derivation
//!
//! TON uses a modified BIP39-like mnemonic system with HMAC-based validation
//! instead of standard BIP39 checksum. Valid mnemonics produce specific
//! bytes when hashed with PBKDF2-HMAC-SHA512.

use crate::error::{WalletError, WalletResult};
use hmac::Hmac;
use pbkdf2::pbkdf2;
use rand::rngs::OsRng;
use rand::Rng;
use sha2::Sha512;

/// BIP39 English wordlist (2048 words)
const WORDLIST: &str = include_str!("wordlist.txt");

/// Number of PBKDF2 iterations for seed derivation
const PBKDF2_ITERATIONS: u32 = 100_000;

/// Salt prefix for TON seed derivation
const TON_SEED_SALT: &str = "TON default seed";

/// Salt for mnemonic validation
const MNEMONIC_SALT: &str = "TON seed version";

/// Mnemonic phrase for wallet key derivation
#[derive(Clone)]
pub struct Mnemonic {
    words: Vec<String>,
}

impl Mnemonic {
    /// Generate a new random 24-word mnemonic with TON validation
    ///
    /// Generates mnemonics until one passes TON's HMAC-based validation.
    /// This ensures the mnemonic is valid according to TON's standards.
    pub fn generate() -> Self {
        let wordlist: Vec<&str> = WORDLIST.lines().collect();
        let mut rng = OsRng;

        loop {
            let words: Vec<String> = (0..24)
                .map(|_| {
                    let idx = rng.gen_range(0..wordlist.len());
                    wordlist[idx].to_string()
                })
                .collect();

            let mnemonic = Self { words };
            if mnemonic.is_valid_ton_mnemonic() {
                return mnemonic;
            }
        }
    }

    /// Generate mnemonic without validation (faster but may not be TON-valid)
    pub fn generate_unchecked() -> Self {
        let wordlist: Vec<&str> = WORDLIST.lines().collect();
        let mut rng = OsRng;

        let words: Vec<String> = (0..24)
            .map(|_| {
                let idx = rng.gen_range(0..wordlist.len());
                wordlist[idx].to_string()
            })
            .collect();

        Self { words }
    }

    /// Parse mnemonic from phrase string with validation
    pub fn from_phrase(phrase: &str) -> WalletResult<Self> {
        let words: Vec<String> = phrase
            .split_whitespace()
            .map(|w| w.to_lowercase())
            .collect();

        if words.len() != 24 {
            return Err(WalletError::WrongWordCount(words.len()));
        }

        let wordlist: Vec<&str> = WORDLIST.lines().collect();
        for word in &words {
            if !wordlist.contains(&word.as_str()) {
                return Err(WalletError::InvalidWord(word.clone()));
            }
        }

        Ok(Self { words })
    }

    /// Parse mnemonic with strict TON validation
    pub fn from_phrase_validated(phrase: &str) -> WalletResult<Self> {
        let mnemonic = Self::from_phrase(phrase)?;
        if !mnemonic.is_valid_ton_mnemonic() {
            return Err(WalletError::InvalidMnemonic(
                "Mnemonic fails TON HMAC validation".to_string(),
            ));
        }
        Ok(mnemonic)
    }

    /// Get the words in this mnemonic
    pub fn words(&self) -> &[String] {
        &self.words
    }

    /// Convert to phrase string
    pub fn to_phrase(&self) -> String {
        self.words.join(" ")
    }

    /// Derive seed bytes using PBKDF2-SHA512
    pub fn to_seed(&self, password: &str) -> [u8; 64] {
        let phrase = self.to_phrase();
        let salt = format!("{}{}", TON_SEED_SALT, password);

        let mut seed = [0u8; 64];
        pbkdf2::<Hmac<Sha512>>(
            phrase.as_bytes(),
            salt.as_bytes(),
            PBKDF2_ITERATIONS,
            &mut seed,
        ).expect("PBKDF2 should not fail");

        seed
    }

    /// Derive Ed25519 keypair from mnemonic
    pub fn to_keypair(&self) -> ton_crypto::Ed25519Keypair {
        let seed = self.to_seed("");

        // Use first 32 bytes for Ed25519 seed
        let mut ed_seed = [0u8; 32];
        ed_seed.copy_from_slice(&seed[..32]);

        ton_crypto::Ed25519Keypair::from_private_key(ed_seed)
    }

    /// Derive keypair with password
    pub fn to_keypair_with_password(&self, password: &str) -> ton_crypto::Ed25519Keypair {
        let seed = self.to_seed(password);

        let mut ed_seed = [0u8; 32];
        ed_seed.copy_from_slice(&seed[..32]);

        ton_crypto::Ed25519Keypair::from_private_key(ed_seed)
    }

    /// Validate that all words are in the wordlist
    pub fn is_valid(&self) -> bool {
        if self.words.len() != 24 {
            return false;
        }

        let wordlist: Vec<&str> = WORDLIST.lines().collect();
        self.words.iter().all(|w| wordlist.contains(&w.as_str()))
    }

    /// Validate mnemonic according to TON's HMAC-based validation
    ///
    /// TON validates mnemonics by checking if PBKDF2-HMAC-SHA512
    /// of the mnemonic produces specific bytes at the beginning.
    pub fn is_valid_ton_mnemonic(&self) -> bool {
        if !self.is_valid() {
            return false;
        }

        // TON mnemonic validation: compute PBKDF2 with "TON seed version" salt
        // and check if first byte is 0x00 (basic validation)
        let phrase = self.to_phrase();
        let mut entropy = [0u8; 64];

        pbkdf2::<Hmac<Sha512>>(
            phrase.as_bytes(),
            MNEMONIC_SALT.as_bytes(),
            PBKDF2_ITERATIONS / 256, // Reduced iterations for validation
            &mut entropy,
        ).expect("PBKDF2 should not fail");

        // Valid TON mnemonic has first byte == 0
        // Per official TON: tonlib/tonlib/keys/Mnemonic.cpp is_basic_seed()
        entropy[0] == 0
    }

    /// Compute entropy bytes from mnemonic (for debugging/verification)
    pub fn entropy(&self) -> [u8; 32] {
        let seed = self.to_seed("");
        let mut entropy = [0u8; 32];
        entropy.copy_from_slice(&seed[..32]);
        entropy
    }
}

impl std::fmt::Debug for Mnemonic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Mnemonic")
            .field("words", &"[REDACTED]")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_mnemonic_unchecked() {
        let mnemonic = Mnemonic::generate_unchecked();
        assert_eq!(mnemonic.words().len(), 24);
        assert!(mnemonic.is_valid());
    }

    #[test]
    fn test_parse_mnemonic() {
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";
        let mnemonic = Mnemonic::from_phrase(phrase).unwrap();
        assert_eq!(mnemonic.words().len(), 24);
    }

    #[test]
    fn test_keypair_derivation() {
        let mnemonic = Mnemonic::generate_unchecked();
        let keypair = mnemonic.to_keypair();
        assert_eq!(keypair.public_key.len(), 32);
    }

    #[test]
    fn test_deterministic_derivation() {
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";
        let m1 = Mnemonic::from_phrase(phrase).unwrap();
        let m2 = Mnemonic::from_phrase(phrase).unwrap();

        let k1 = m1.to_keypair();
        let k2 = m2.to_keypair();

        assert_eq!(k1.public_key, k2.public_key);
    }

    #[test]
    fn test_ton_mnemonic_validation() {
        // Test that validation correctly identifies valid/invalid mnemonics
        let mnemonic = Mnemonic::generate_unchecked();
        // Most unchecked mnemonics won't pass TON validation
        // but the validation function should work without error
        let _ = mnemonic.is_valid_ton_mnemonic();
    }

    #[test]
    fn test_entropy_deterministic() {
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";
        let m1 = Mnemonic::from_phrase(phrase).unwrap();
        let m2 = Mnemonic::from_phrase(phrase).unwrap();

        assert_eq!(m1.entropy(), m2.entropy());
    }
}
