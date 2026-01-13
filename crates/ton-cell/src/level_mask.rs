//! LevelMask implementation based on official TON code.
//!
//! LevelMask is used to track which levels contain meaningful hash data
//! in a Merkle tree structure. This is critical for exotic cells like
//! PrunedBranch, MerkleProof, and MerkleUpdate.
//!
//! Reference: ton-blockchain/ton/crypto/vm/cells/LevelMask.h

/// Maximum cell level (0-3).
pub const MAX_LEVEL: u8 = 3;

/// LevelMask tracks which levels contain meaningful hashes.
///
/// In TON, cells can have hashes at multiple levels (0-3).
/// The level mask indicates which levels are "significant" and contain
/// pre-computed hashes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct LevelMask {
    mask: u8,
}

impl LevelMask {
    /// Create a new LevelMask with the given mask value.
    #[inline]
    pub fn new(mask: u8) -> Self {
        Self { mask: mask & 0x07 } // Only 3 bits are used (levels 0-3)
    }

    /// Create a LevelMask with all bits set (all levels significant).
    #[inline]
    pub fn all() -> Self {
        Self { mask: 0x07 }
    }

    /// Create a LevelMask for a single level.
    ///
    /// For level 0, returns mask 0.
    /// For level n > 0, returns mask with bit (n-1) set.
    #[inline]
    pub fn one_level(level: u8) -> Self {
        if level == 0 {
            Self::new(0)
        } else {
            Self::new(1 << (level - 1))
        }
    }

    /// Get the raw mask value.
    #[inline]
    pub fn get_mask(&self) -> u8 {
        self.mask
    }

    /// Get the level (position of highest set bit + 1).
    ///
    /// Returns 0 if mask is 0, otherwise 32 - leading_zeros.
    #[inline]
    pub fn get_level(&self) -> u8 {
        if self.mask == 0 {
            0
        } else {
            8 - self.mask.leading_zeros() as u8
        }
    }

    /// Get the hash index (number of set bits).
    ///
    /// This tells us how many hashes are stored before the current level.
    #[inline]
    pub fn get_hash_index(&self) -> u8 {
        self.mask.count_ones() as u8
    }

    /// Get the total number of hashes (hash_index + 1).
    #[inline]
    pub fn get_hashes_count(&self) -> u8 {
        self.get_hash_index() + 1
    }

    /// Apply a level filter, keeping only bits below the specified level.
    ///
    /// `apply(level)` returns a mask with bits 0..(level-1) preserved.
    /// This is used when computing hash at a specific level.
    #[inline]
    pub fn apply(&self, level: u8) -> Self {
        if level == 0 {
            Self::new(0)
        } else {
            Self::new(self.mask & ((1u8 << level) - 1))
        }
    }

    /// Combine with another mask using OR.
    ///
    /// Used for ordinary cells: level_mask = OR of all children's masks.
    #[inline]
    pub fn apply_or(&self, other: LevelMask) -> Self {
        Self::new(self.mask | other.mask)
    }

    /// Shift the mask right by 1.
    ///
    /// Used for MerkleProof/MerkleUpdate cells.
    #[inline]
    pub fn shift_right(&self) -> Self {
        Self::new(self.mask >> 1)
    }

    /// Check if a level is significant.
    ///
    /// Level 0 is always significant.
    /// For level > 0, check if bit (level-1) is set.
    #[inline]
    pub fn is_significant(&self, level: u8) -> bool {
        level == 0 || ((self.mask >> (level - 1)) & 1) != 0
    }
}

impl From<u8> for LevelMask {
    fn from(mask: u8) -> Self {
        Self::new(mask)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new() {
        let mask = LevelMask::new(0b101);
        assert_eq!(mask.get_mask(), 0b101);

        // Should mask to 3 bits
        let mask = LevelMask::new(0xFF);
        assert_eq!(mask.get_mask(), 0x07);
    }

    #[test]
    fn test_get_level() {
        assert_eq!(LevelMask::new(0b000).get_level(), 0);
        assert_eq!(LevelMask::new(0b001).get_level(), 1);
        assert_eq!(LevelMask::new(0b010).get_level(), 2);
        assert_eq!(LevelMask::new(0b011).get_level(), 2);
        assert_eq!(LevelMask::new(0b100).get_level(), 3);
        assert_eq!(LevelMask::new(0b111).get_level(), 3);
    }

    #[test]
    fn test_get_hash_index() {
        assert_eq!(LevelMask::new(0b000).get_hash_index(), 0);
        assert_eq!(LevelMask::new(0b001).get_hash_index(), 1);
        assert_eq!(LevelMask::new(0b010).get_hash_index(), 1);
        assert_eq!(LevelMask::new(0b011).get_hash_index(), 2);
        assert_eq!(LevelMask::new(0b111).get_hash_index(), 3);
    }

    #[test]
    fn test_apply() {
        let mask = LevelMask::new(0b111);
        assert_eq!(mask.apply(0).get_mask(), 0b000);
        assert_eq!(mask.apply(1).get_mask(), 0b001);
        assert_eq!(mask.apply(2).get_mask(), 0b011);
        assert_eq!(mask.apply(3).get_mask(), 0b111);
    }

    #[test]
    fn test_apply_or() {
        let a = LevelMask::new(0b101);
        let b = LevelMask::new(0b011);
        assert_eq!(a.apply_or(b).get_mask(), 0b111);
    }

    #[test]
    fn test_shift_right() {
        assert_eq!(LevelMask::new(0b110).shift_right().get_mask(), 0b011);
        assert_eq!(LevelMask::new(0b001).shift_right().get_mask(), 0b000);
    }

    #[test]
    fn test_is_significant() {
        let mask = LevelMask::new(0b101);
        assert!(mask.is_significant(0)); // Level 0 always significant
        assert!(mask.is_significant(1)); // Bit 0 is set
        assert!(!mask.is_significant(2)); // Bit 1 is not set
        assert!(mask.is_significant(3)); // Bit 2 is set
    }

    #[test]
    fn test_one_level() {
        assert_eq!(LevelMask::one_level(0).get_mask(), 0b000);
        assert_eq!(LevelMask::one_level(1).get_mask(), 0b001);
        assert_eq!(LevelMask::one_level(2).get_mask(), 0b010);
        assert_eq!(LevelMask::one_level(3).get_mask(), 0b100);
    }
}
