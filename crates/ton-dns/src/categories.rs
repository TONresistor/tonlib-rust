//! Standard DNS categories for TON DNS records.
//!
//! DNS records are organized by category, where each category is identified
//! by the SHA256 hash of a string identifier.
//!
//! # Standard Categories
//!
//! - `dns_next_resolver` - Points to the next resolver contract
//! - `wallet` - Smart contract address for payments
//! - `site` - ADNL address for TON Sites
//! - `storage` - TON Storage bag ID

use ton_crypto::sha256;

/// DNS category as a 32-byte identifier.
pub type DnsCategory = [u8; 32];

/// Category for the next resolver contract.
///
/// Used during iterative resolution to find the next contract
/// that can resolve the remaining domain components.
pub const DNS_CATEGORY_NEXT_RESOLVER: DnsCategory = compute_category(b"dns_next_resolver");

/// Category for wallet/smart contract addresses.
///
/// Used to look up the payment address associated with a domain.
pub const DNS_CATEGORY_WALLET: DnsCategory = compute_category(b"wallet");

/// Category for TON Sites (ADNL addresses).
///
/// Used to resolve domain names to TON Site addresses.
pub const DNS_CATEGORY_SITE: DnsCategory = compute_category(b"site");

/// Category for TON Storage bag IDs.
///
/// Used to resolve domain names to storage locations.
pub const DNS_CATEGORY_STORAGE: DnsCategory = compute_category(b"storage");

/// Zero category - used to query all categories.
pub const DNS_CATEGORY_ALL: DnsCategory = [0u8; 32];

/// Compute a DNS category from its string identifier.
///
/// This function uses compile-time computation where possible.
const fn compute_category(name: &[u8]) -> DnsCategory {
    // SHA256 computation at compile time is complex, so we use a helper
    // that will be evaluated at compile time for const contexts
    sha256_const(name)
}

/// Compile-time SHA256 implementation.
///
/// This is a simplified version that works at compile time.
/// For runtime computation, use `category_from_name()`.
const fn sha256_const(data: &[u8]) -> [u8; 32] {
    // Initial hash values (first 32 bits of fractional parts of square roots of first 8 primes)
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    ];

    // Round constants
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    ];

    // Prepare message with padding
    let msg_len = data.len();
    let bit_len = (msg_len as u64) * 8;

    // Calculate padded length: message + 1 byte (0x80) + padding + 8 bytes (length)
    // Must be multiple of 64 bytes
    let padded_len = (msg_len + 9).div_ceil(64) * 64;

    // Create padded message (max 128 bytes for short inputs)
    let mut padded = [0u8; 128];
    let mut i = 0;
    while i < msg_len {
        padded[i] = data[i];
        i += 1;
    }
    padded[msg_len] = 0x80;

    // Add length in big-endian at the end
    padded[padded_len - 8] = (bit_len >> 56) as u8;
    padded[padded_len - 7] = (bit_len >> 48) as u8;
    padded[padded_len - 6] = (bit_len >> 40) as u8;
    padded[padded_len - 5] = (bit_len >> 32) as u8;
    padded[padded_len - 4] = (bit_len >> 24) as u8;
    padded[padded_len - 3] = (bit_len >> 16) as u8;
    padded[padded_len - 2] = (bit_len >> 8) as u8;
    padded[padded_len - 1] = bit_len as u8;

    // Process each 64-byte chunk
    let mut chunk_start = 0;
    while chunk_start < padded_len {
        // Prepare message schedule
        let mut w = [0u32; 64];

        let mut t = 0;
        while t < 16 {
            let idx = chunk_start + t * 4;
            w[t] = ((padded[idx] as u32) << 24)
                | ((padded[idx + 1] as u32) << 16)
                | ((padded[idx + 2] as u32) << 8)
                | (padded[idx + 3] as u32);
            t += 1;
        }

        while t < 64 {
            let s0 = w[t - 15].rotate_right(7) ^ w[t - 15].rotate_right(18) ^ (w[t - 15] >> 3);
            let s1 = w[t - 2].rotate_right(17) ^ w[t - 2].rotate_right(19) ^ (w[t - 2] >> 10);
            w[t] = w[t - 16].wrapping_add(s0).wrapping_add(w[t - 7]).wrapping_add(s1);
            t += 1;
        }

        // Initialize working variables
        let mut a = h[0];
        let mut b = h[1];
        let mut c = h[2];
        let mut d = h[3];
        let mut e = h[4];
        let mut f = h[5];
        let mut g = h[6];
        let mut hh = h[7];

        // Compression function
        t = 0;
        while t < 64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = hh.wrapping_add(s1).wrapping_add(ch).wrapping_add(K[t]).wrapping_add(w[t]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);

            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
            t += 1;
        }

        // Add to hash
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);

        chunk_start += 64;
    }

    // Produce final hash
    [
        (h[0] >> 24) as u8, (h[0] >> 16) as u8, (h[0] >> 8) as u8, h[0] as u8,
        (h[1] >> 24) as u8, (h[1] >> 16) as u8, (h[1] >> 8) as u8, h[1] as u8,
        (h[2] >> 24) as u8, (h[2] >> 16) as u8, (h[2] >> 8) as u8, h[2] as u8,
        (h[3] >> 24) as u8, (h[3] >> 16) as u8, (h[3] >> 8) as u8, h[3] as u8,
        (h[4] >> 24) as u8, (h[4] >> 16) as u8, (h[4] >> 8) as u8, h[4] as u8,
        (h[5] >> 24) as u8, (h[5] >> 16) as u8, (h[5] >> 8) as u8, h[5] as u8,
        (h[6] >> 24) as u8, (h[6] >> 16) as u8, (h[6] >> 8) as u8, h[6] as u8,
        (h[7] >> 24) as u8, (h[7] >> 16) as u8, (h[7] >> 8) as u8, h[7] as u8,
    ]
}

/// Compute a DNS category from its name at runtime.
///
/// This uses the ton-crypto SHA256 implementation for better performance.
///
/// # Examples
///
/// ```
/// use ton_dns::categories::{category_from_name, DNS_CATEGORY_WALLET};
///
/// let wallet_cat = category_from_name("wallet");
/// assert_eq!(wallet_cat, DNS_CATEGORY_WALLET);
/// ```
pub fn category_from_name(name: &str) -> DnsCategory {
    sha256(name.as_bytes())
}

/// Get the human-readable name for a known category.
///
/// Returns `None` for unknown categories.
///
/// # Examples
///
/// ```
/// use ton_dns::categories::{category_name, DNS_CATEGORY_WALLET, DNS_CATEGORY_SITE};
///
/// assert_eq!(category_name(&DNS_CATEGORY_WALLET), Some("wallet"));
/// assert_eq!(category_name(&DNS_CATEGORY_SITE), Some("site"));
/// assert_eq!(category_name(&[0xFF; 32]), None);
/// ```
pub fn category_name(category: &DnsCategory) -> Option<&'static str> {
    if *category == DNS_CATEGORY_NEXT_RESOLVER {
        Some("dns_next_resolver")
    } else if *category == DNS_CATEGORY_WALLET {
        Some("wallet")
    } else if *category == DNS_CATEGORY_SITE {
        Some("site")
    } else if *category == DNS_CATEGORY_STORAGE {
        Some("storage")
    } else if *category == DNS_CATEGORY_ALL {
        Some("all")
    } else {
        None
    }
}

/// Check if a category is the "all categories" query.
pub fn is_all_categories(category: &DnsCategory) -> bool {
    *category == DNS_CATEGORY_ALL
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_category_wallet() {
        let expected = sha256(b"wallet");
        assert_eq!(DNS_CATEGORY_WALLET, expected);
        assert_eq!(category_from_name("wallet"), DNS_CATEGORY_WALLET);
    }

    #[test]
    fn test_category_site() {
        let expected = sha256(b"site");
        assert_eq!(DNS_CATEGORY_SITE, expected);
        assert_eq!(category_from_name("site"), DNS_CATEGORY_SITE);
    }

    #[test]
    fn test_category_storage() {
        let expected = sha256(b"storage");
        assert_eq!(DNS_CATEGORY_STORAGE, expected);
        assert_eq!(category_from_name("storage"), DNS_CATEGORY_STORAGE);
    }

    #[test]
    fn test_category_next_resolver() {
        let expected = sha256(b"dns_next_resolver");
        assert_eq!(DNS_CATEGORY_NEXT_RESOLVER, expected);
        assert_eq!(category_from_name("dns_next_resolver"), DNS_CATEGORY_NEXT_RESOLVER);
    }

    #[test]
    fn test_category_all() {
        assert_eq!(DNS_CATEGORY_ALL, [0u8; 32]);
        assert!(is_all_categories(&DNS_CATEGORY_ALL));
        assert!(!is_all_categories(&DNS_CATEGORY_WALLET));
    }

    #[test]
    fn test_category_name() {
        assert_eq!(category_name(&DNS_CATEGORY_WALLET), Some("wallet"));
        assert_eq!(category_name(&DNS_CATEGORY_SITE), Some("site"));
        assert_eq!(category_name(&DNS_CATEGORY_STORAGE), Some("storage"));
        assert_eq!(category_name(&DNS_CATEGORY_NEXT_RESOLVER), Some("dns_next_resolver"));
        assert_eq!(category_name(&DNS_CATEGORY_ALL), Some("all"));
        assert_eq!(category_name(&[0xFF; 32]), None);
    }

    #[test]
    fn test_custom_category() {
        let custom = category_from_name("my_custom_category");
        assert_eq!(custom, sha256(b"my_custom_category"));
        assert_eq!(category_name(&custom), None);
    }
}
