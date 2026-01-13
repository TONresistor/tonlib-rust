//! Overlay ID calculation.
//!
//! Overlay IDs identify specific overlay networks in TON.
//! For shardchain overlays, the ID is computed from workchain, shard, and zero_state_hash.

use ton_crypto::sha256;

use crate::tl::{TlWriter, TON_NODE_SHARD_PUBLIC_OVERLAY_ID};

/// Overlay ID - a 256-bit identifier for an overlay network.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct OverlayId([u8; 32]);

impl OverlayId {
    /// Creates an OverlayId from raw bytes.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the overlay ID as a byte slice.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Returns the overlay ID as a byte array.
    pub fn to_bytes(self) -> [u8; 32] {
        self.0
    }

    /// Calculates the overlay ID for a shard overlay.
    ///
    /// This computes the overlay ID from:
    /// - workchain: The workchain ID (e.g., -1 for masterchain, 0 for basechain)
    /// - shard: The shard ID (64-bit shard prefix)
    /// - zero_state_hash: The hash of the zero state file
    ///
    /// The formula is:
    /// ```text
    /// SHA256(tonNode.shardPublicOverlayId workchain:int shard:long zero_state_file_hash:int256)
    /// ```
    pub fn for_shard(workchain: i32, shard: i64, zero_state_hash: &[u8; 32]) -> Self {
        let mut writer = TlWriter::new();
        writer.write_u32(TON_NODE_SHARD_PUBLIC_OVERLAY_ID);
        writer.write_i32(workchain);
        writer.write_i64(shard);
        writer.write_int256(zero_state_hash);

        let hash = sha256(&writer.finish());
        Self(hash)
    }

    /// Calculates the overlay ID for a masterchain overlay.
    ///
    /// The masterchain has workchain ID -1 and a full shard (0x8000000000000000).
    pub fn for_masterchain(zero_state_hash: &[u8; 32]) -> Self {
        Self::for_shard(-1, i64::MIN, zero_state_hash)
    }

    /// Calculates the overlay ID for a basechain overlay (workchain 0).
    ///
    /// The basechain has workchain ID 0 and a full shard (0x8000000000000000).
    pub fn for_basechain(zero_state_hash: &[u8; 32]) -> Self {
        Self::for_shard(0, i64::MIN, zero_state_hash)
    }

    /// Creates an overlay ID from arbitrary data (for private overlays).
    ///
    /// This is useful for creating custom overlay networks not tied to shards.
    pub fn from_data(data: &[u8]) -> Self {
        let hash = sha256(data);
        Self(hash)
    }
}

impl AsRef<[u8; 32]> for OverlayId {
    fn as_ref(&self) -> &[u8; 32] {
        &self.0
    }
}

impl From<[u8; 32]> for OverlayId {
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl From<OverlayId> for [u8; 32] {
    fn from(id: OverlayId) -> Self {
        id.0
    }
}

impl std::fmt::Display for OverlayId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for byte in &self.0 {
            write!(f, "{:02x}", byte)?;
        }
        Ok(())
    }
}

/// Helper function to calculate overlay ID for a shard.
pub fn calculate_overlay_id(workchain: i32, shard: i64, zero_state_hash: &[u8; 32]) -> [u8; 32] {
    OverlayId::for_shard(workchain, shard, zero_state_hash).to_bytes()
}

/// Calculates the DHT key for looking up overlay nodes.
///
/// The DHT key is derived from the overlay ID with a specific name prefix.
pub fn dht_key_for_overlay(overlay_id: &[u8; 32]) -> [u8; 32] {
    // The DHT key for overlay is: SHA256("nodes" || overlay_id)
    let mut data = Vec::with_capacity(5 + 32);
    data.extend_from_slice(b"nodes");
    data.extend_from_slice(overlay_id);
    sha256(&data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_overlay_id_from_bytes() {
        let bytes = [42u8; 32];
        let id = OverlayId::from_bytes(bytes);
        assert_eq!(id.as_bytes(), &bytes);
    }

    #[test]
    fn test_overlay_id_for_shard() {
        let zero_state_hash = [1u8; 32];

        // Test masterchain overlay
        let mc_id = OverlayId::for_masterchain(&zero_state_hash);
        let mc_id2 = OverlayId::for_shard(-1, i64::MIN, &zero_state_hash);
        assert_eq!(mc_id, mc_id2);

        // Test basechain overlay
        let bc_id = OverlayId::for_basechain(&zero_state_hash);
        let bc_id2 = OverlayId::for_shard(0, i64::MIN, &zero_state_hash);
        assert_eq!(bc_id, bc_id2);

        // Masterchain and basechain should have different IDs
        assert_ne!(mc_id, bc_id);
    }

    #[test]
    fn test_overlay_id_deterministic() {
        let zero_state_hash = [5u8; 32];

        let id1 = OverlayId::for_shard(0, i64::MIN, &zero_state_hash);
        let id2 = OverlayId::for_shard(0, i64::MIN, &zero_state_hash);

        assert_eq!(id1, id2);
    }

    #[test]
    fn test_overlay_id_different_params() {
        let zero_state_hash = [5u8; 32];

        // Different workchains
        let id1 = OverlayId::for_shard(0, i64::MIN, &zero_state_hash);
        let id2 = OverlayId::for_shard(1, i64::MIN, &zero_state_hash);
        assert_ne!(id1, id2);

        // Different shards
        let id3 = OverlayId::for_shard(0, i64::MIN, &zero_state_hash);
        let id4 = OverlayId::for_shard(0, 0x4000000000000000, &zero_state_hash);
        assert_ne!(id3, id4);

        // Different zero state hash
        let other_hash = [6u8; 32];
        let id5 = OverlayId::for_shard(0, i64::MIN, &zero_state_hash);
        let id6 = OverlayId::for_shard(0, i64::MIN, &other_hash);
        assert_ne!(id5, id6);
    }

    #[test]
    fn test_overlay_id_display() {
        let bytes = [0xABu8; 32];
        let id = OverlayId::from_bytes(bytes);
        let display = format!("{}", id);
        assert_eq!(display.len(), 64); // 32 bytes * 2 hex chars
        assert!(display.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_overlay_id_from_data() {
        let data = b"my custom overlay network";
        let id = OverlayId::from_data(data);

        // Should be deterministic
        let id2 = OverlayId::from_data(data);
        assert_eq!(id, id2);

        // Different data should give different IDs
        let id3 = OverlayId::from_data(b"other overlay");
        assert_ne!(id, id3);
    }

    #[test]
    fn test_dht_key_for_overlay() {
        let overlay_id = [42u8; 32];
        let key = dht_key_for_overlay(&overlay_id);

        // Should be deterministic
        let key2 = dht_key_for_overlay(&overlay_id);
        assert_eq!(key, key2);

        // Different overlay IDs should give different keys
        let other_id = [43u8; 32];
        let key3 = dht_key_for_overlay(&other_id);
        assert_ne!(key, key3);
    }

    #[test]
    fn test_calculate_overlay_id() {
        let zero_state_hash = [1u8; 32];

        let id = calculate_overlay_id(-1, i64::MIN, &zero_state_hash);
        let id2 = OverlayId::for_masterchain(&zero_state_hash).to_bytes();

        assert_eq!(id, id2);
    }
}
