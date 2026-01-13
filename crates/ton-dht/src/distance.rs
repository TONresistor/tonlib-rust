//! XOR distance calculations for Kademlia DHT.
//!
//! In Kademlia, the distance between two nodes is calculated using XOR on their
//! node IDs. This gives us a metric where:
//! - Smaller XOR values indicate closer nodes
//! - The distance is symmetric: d(a, b) = d(b, a)
//! - Triangle inequality holds: d(a, c) <= d(a, b) + d(b, c)

use std::cmp::Ordering;

/// A 256-bit XOR distance value.
///
/// The distance is stored as a big-endian byte array, where the first byte
/// is the most significant. This allows for natural lexicographic ordering.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Distance(pub [u8; 32]);

impl Distance {
    /// Creates a new distance from raw bytes.
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the zero distance.
    pub fn zero() -> Self {
        Self([0u8; 32])
    }

    /// Returns the maximum distance.
    pub fn max() -> Self {
        Self([0xFF; 32])
    }

    /// Returns the distance as bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Checks if the distance is zero.
    pub fn is_zero(&self) -> bool {
        self.0.iter().all(|&b| b == 0)
    }

    /// Counts the number of leading zero bits in the distance.
    ///
    /// This is the primary metric for bucket assignment in TON DHT.
    /// Returns 256 if all bits are zero (identical nodes).
    pub fn count_leading_zeroes(&self) -> usize {
        for (byte_idx, &byte) in self.0.iter().enumerate() {
            if byte != 0 {
                return byte_idx * 8 + byte.leading_zeros() as usize;
            }
        }
        256
    }

    /// Returns the index of the highest set bit (0-255).
    ///
    /// Returns None if the distance is zero.
    #[deprecated(note = "Use count_leading_zeroes() for bucket assignment")]
    pub fn highest_bit(&self) -> Option<usize> {
        for (byte_idx, &byte) in self.0.iter().enumerate() {
            if byte != 0 {
                let bit_idx = 7 - byte.leading_zeros() as usize;
                return Some((31 - byte_idx) * 8 + bit_idx);
            }
        }
        None
    }

    /// Returns the bucket index for this distance.
    ///
    /// In TON DHT (following official implementation):
    /// bucket_index = count_leading_zeroes(XOR_distance)
    ///
    /// - Bucket 0: nodes differing at MSB (bit 255) - largest distance
    /// - Bucket 255: nodes differing only at bit 0 - smallest distance
    ///
    /// Returns 256 for zero distance (identical nodes - should not be added).
    pub fn bucket_index(&self) -> usize {
        self.count_leading_zeroes()
    }
}

impl PartialOrd for Distance {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Distance {
    fn cmp(&self, other: &Self) -> Ordering {
        // Compare byte by byte (big-endian order)
        for i in 0..32 {
            match self.0[i].cmp(&other.0[i]) {
                Ordering::Equal => continue,
                ord => return ord,
            }
        }
        Ordering::Equal
    }
}

impl Default for Distance {
    fn default() -> Self {
        Self::zero()
    }
}

/// Calculates the XOR distance between two 256-bit node IDs.
///
/// The result is a 256-bit value where smaller values indicate closer nodes.
///
/// # Example
///
/// ```
/// use ton_dht::distance::xor_distance;
///
/// let a = [0x00u8; 32];
/// let mut b = [0x00u8; 32];
/// b[31] = 0x01; // b differs only in the last bit
///
/// let dist = xor_distance(&a, &b);
/// assert_eq!(dist.as_bytes()[31], 0x01);
/// // Bucket 255: 31 zero bytes + 7 leading zeros in byte 0x01 = 255 leading zeros
/// assert_eq!(dist.bucket_index(), 255);
/// ```
pub fn xor_distance(a: &[u8; 32], b: &[u8; 32]) -> Distance {
    let mut result = [0u8; 32];
    for i in 0..32 {
        result[i] = a[i] ^ b[i];
    }
    Distance(result)
}

/// Determines if node `a` is closer to `target` than node `b`.
///
/// Returns true if distance(target, a) < distance(target, b).
///
/// # Example
///
/// ```
/// use ton_dht::distance::is_closer;
///
/// let target = [0x00u8; 32];
/// let mut a = [0x00u8; 32];
/// let mut b = [0x00u8; 32];
///
/// a[31] = 0x01; // distance 1
/// b[31] = 0x02; // distance 2
///
/// assert!(is_closer(&target, &a, &b));
/// assert!(!is_closer(&target, &b, &a));
/// ```
pub fn is_closer(target: &[u8; 32], a: &[u8; 32], b: &[u8; 32]) -> bool {
    xor_distance(target, a) < xor_distance(target, b)
}

/// Compares two nodes by their distance to a target.
///
/// Returns Ordering::Less if `a` is closer to `target` than `b`.
pub fn compare_distance(target: &[u8; 32], a: &[u8; 32], b: &[u8; 32]) -> Ordering {
    xor_distance(target, a).cmp(&xor_distance(target, b))
}

/// Returns the common prefix length between two node IDs.
///
/// This is the number of leading bits that are identical.
/// For identical nodes, returns 256 (all bits match).
/// For nodes differing at MSB, returns 0 (no bits match before first difference).
/// For nodes differing only at LSB, returns 255 (first 255 bits match).
pub fn common_prefix_length(a: &[u8; 32], b: &[u8; 32]) -> usize {
    let distance = xor_distance(a, b);
    // Common prefix length = number of leading zero bits in XOR distance
    // This equals the bucket_index for non-zero distances
    distance.count_leading_zeroes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xor_distance_same() {
        let id = [42u8; 32];
        let dist = xor_distance(&id, &id);
        assert!(dist.is_zero());
        // Zero distance (identical nodes) returns 256 leading zeros
        assert_eq!(dist.bucket_index(), 256);
    }

    #[test]
    fn test_xor_distance_different() {
        let a = [0u8; 32];
        let mut b = [0u8; 32];
        b[31] = 1;

        let dist = xor_distance(&a, &b);
        assert_eq!(dist.0[31], 1);
        // Distance 1 (LSB set) = 255 leading zeros → bucket 255 (closest non-self)
        assert_eq!(dist.bucket_index(), 255);
    }

    #[test]
    fn test_bucket_index() {
        let a = [0u8; 32];

        // TON bucket assignment: bucket_index = count_leading_zeroes
        // More leading zeros = closer node = higher bucket number

        // Distance with only bit 0 set (value 1 in LSB) - closest distance
        // 31 zero bytes + 7 leading zeros in 0x01 = 255 leading zeros
        let mut b1 = [0u8; 32];
        b1[31] = 0x01;
        assert_eq!(xor_distance(&a, &b1).bucket_index(), 255);

        // Distance with bit 7 set in LSB (value 128)
        // 31 zero bytes + 0 leading zeros in 0x80 = 248 leading zeros
        let mut b2 = [0u8; 32];
        b2[31] = 0x80;
        assert_eq!(xor_distance(&a, &b2).bucket_index(), 248);

        // Distance with bit set in second-to-last byte
        // 30 zero bytes + 7 leading zeros in 0x01 = 247 leading zeros
        let mut b3 = [0u8; 32];
        b3[30] = 0x01;
        assert_eq!(xor_distance(&a, &b3).bucket_index(), 247);

        // Distance with MSB set (farthest distance)
        // 0 leading zeros in 0x80 = 0 leading zeros
        let mut b4 = [0u8; 32];
        b4[0] = 0x80;
        assert_eq!(xor_distance(&a, &b4).bucket_index(), 0);
    }

    #[test]
    fn test_is_closer() {
        let target = [0u8; 32];

        let mut a = [0u8; 32];
        a[31] = 0x01; // distance 1

        let mut b = [0u8; 32];
        b[31] = 0x02; // distance 2

        assert!(is_closer(&target, &a, &b));
        assert!(!is_closer(&target, &b, &a));
        assert!(!is_closer(&target, &a, &a)); // equal distances
    }

    #[test]
    fn test_distance_ordering() {
        let d1 = Distance::new([0u8; 32]);
        let mut d2_bytes = [0u8; 32];
        d2_bytes[31] = 1;
        let d2 = Distance::new(d2_bytes);
        let d3 = Distance::max();

        assert!(d1 < d2);
        assert!(d2 < d3);
        assert!(d1 < d3);
    }

    #[test]
    fn test_common_prefix_length() {
        let a = [0u8; 32];
        let b = [0u8; 32];
        assert_eq!(common_prefix_length(&a, &b), 256);

        let mut c = [0u8; 32];
        c[31] = 0x01;
        assert_eq!(common_prefix_length(&a, &c), 255);

        let mut d = [0u8; 32];
        d[0] = 0x80;
        assert_eq!(common_prefix_length(&a, &d), 0);
    }

    #[test]
    fn test_symmetric_distance() {
        use rand::RngCore;
        let mut rng = rand::thread_rng();

        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        rng.fill_bytes(&mut a);
        rng.fill_bytes(&mut b);

        assert_eq!(xor_distance(&a, &b), xor_distance(&b, &a));
    }

    #[test]
    #[allow(deprecated)]
    fn test_highest_bit() {
        let zero = Distance::zero();
        assert_eq!(zero.highest_bit(), None);

        let mut one_bytes = [0u8; 32];
        one_bytes[31] = 1;
        let one = Distance::new(one_bytes);
        assert_eq!(one.highest_bit(), Some(0));

        let mut high_bytes = [0u8; 32];
        high_bytes[0] = 0x80;
        let high = Distance::new(high_bytes);
        assert_eq!(high.highest_bit(), Some(255));
    }
}
