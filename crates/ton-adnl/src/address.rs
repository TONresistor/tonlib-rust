//! ADNL address types.
//!
//! ADNL addresses are derived from Ed25519 public keys using SHA256 hashing.
//! The address is computed as: SHA256(TL_PREFIX || public_key)
//! where TL_PREFIX is 0x4813b4c6 (pub.ed25519) in little-endian format.

use ton_crypto::keys::calculate_key_id;

/// An ADNL address (256-bit identifier).
///
/// ADNL addresses are used to identify peers in the ADNL network.
/// They are derived from Ed25519 public keys.
///
/// # Example
///
/// ```rust
/// use ton_adnl::AdnlAddress;
/// use ton_crypto::ed25519::Ed25519Keypair;
///
/// let keypair = Ed25519Keypair::generate();
/// let address = AdnlAddress::from_public_key(&keypair.public_key);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AdnlAddress([u8; 32]);

impl AdnlAddress {
    /// Creates an ADNL address from an Ed25519 public key.
    ///
    /// The address is computed as SHA256 of the TL-serialized public key:
    /// `SHA256(0x4813b4c6 || public_key)` where the prefix is in little-endian.
    ///
    /// # Arguments
    ///
    /// * `public_key` - The 32-byte Ed25519 public key.
    ///
    /// # Example
    ///
    /// ```rust
    /// use ton_adnl::AdnlAddress;
    ///
    /// let pubkey = [0u8; 32];
    /// let address = AdnlAddress::from_public_key(&pubkey);
    /// ```
    pub fn from_public_key(public_key: &[u8; 32]) -> Self {
        // Use the calculate_key_id function from ton-crypto which does:
        // SHA256(TL_PREFIX_ED25519 || public_key)
        AdnlAddress(calculate_key_id(public_key))
    }

    /// Creates an ADNL address from raw bytes.
    ///
    /// Use this when you already have a computed address (e.g., from a liteserver config).
    ///
    /// # Arguments
    ///
    /// * `bytes` - The 32-byte address.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        AdnlAddress(bytes)
    }

    /// Returns the address as a byte slice.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Returns the address as a byte array.
    pub fn to_bytes(self) -> [u8; 32] {
        self.0
    }
}

impl From<[u8; 32]> for AdnlAddress {
    fn from(bytes: [u8; 32]) -> Self {
        AdnlAddress(bytes)
    }
}

impl From<AdnlAddress> for [u8; 32] {
    fn from(address: AdnlAddress) -> Self {
        address.0
    }
}

impl AsRef<[u8; 32]> for AdnlAddress {
    fn as_ref(&self) -> &[u8; 32] {
        &self.0
    }
}

impl AsRef<[u8]> for AdnlAddress {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// Computes the Key ID for an Ed25519 public key.
///
/// This is the same as creating an ADNL address from the public key.
/// The Key ID is used in the ADNL handshake to identify the server.
///
/// # Arguments
///
/// * `public_key` - The 32-byte Ed25519 public key.
///
/// # Returns
///
/// The 32-byte Key ID.
pub fn compute_key_id(public_key: &[u8; 32]) -> [u8; 32] {
    calculate_key_id(public_key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ton_crypto::ed25519::Ed25519Keypair;

    #[test]
    fn test_address_from_public_key() {
        let keypair = Ed25519Keypair::generate();
        let address = AdnlAddress::from_public_key(&keypair.public_key);

        // Address should be 32 bytes
        assert_eq!(address.as_bytes().len(), 32);

        // Same key should produce same address
        let address2 = AdnlAddress::from_public_key(&keypair.public_key);
        assert_eq!(address, address2);
    }

    #[test]
    fn test_address_from_bytes() {
        let bytes = [42u8; 32];
        let address = AdnlAddress::from_bytes(bytes);
        assert_eq!(address.as_bytes(), &bytes);
    }

    #[test]
    fn test_different_keys_different_addresses() {
        let keypair1 = Ed25519Keypair::generate();
        let keypair2 = Ed25519Keypair::generate();

        let address1 = AdnlAddress::from_public_key(&keypair1.public_key);
        let address2 = AdnlAddress::from_public_key(&keypair2.public_key);

        assert_ne!(address1, address2);
    }

    #[test]
    fn test_key_id_matches_address() {
        let keypair = Ed25519Keypair::generate();
        let address = AdnlAddress::from_public_key(&keypair.public_key);
        let key_id = compute_key_id(&keypair.public_key);

        assert_eq!(address.as_bytes(), &key_id);
    }

    #[test]
    fn test_conversions() {
        let bytes = [123u8; 32];
        let address = AdnlAddress::from(bytes);

        let back: [u8; 32] = address.into();
        assert_eq!(bytes, back);
    }
}
