//! TON Message Address types.
//!
//! This module provides the MsgAddress enum for representing TON addresses
//! in their various forms (null, external, internal).

use crate::{CellError, CellResult};

/// TON Message Address.
///
/// Addresses in TON can be:
/// - Null (addr_none): No address
/// - External (addr_extern): External address with variable length
/// - Internal (addr_std or addr_var): Standard TON address with workchain and 256-bit hash
///
/// # Example
///
/// ```
/// use ton_cell::MsgAddress;
///
/// // Parse from string
/// let addr = MsgAddress::from_string("0:0000000000000000000000000000000000000000000000000000000000000000").unwrap();
///
/// // Create internal address
/// let addr = MsgAddress::Internal {
///     workchain: 0,
///     address: [0u8; 32],
/// };
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum MsgAddress {
    /// No address (addr_none$00).
    #[default]
    Null,

    /// External address (addr_extern$01).
    External {
        /// Length in bits.
        len: u16,
        /// Address data.
        data: Vec<u8>,
    },

    /// Internal address (addr_std$10 or addr_var$11).
    Internal {
        /// Workchain ID (-1 for masterchain, 0 for basechain).
        workchain: i32,
        /// 256-bit address (account ID).
        address: [u8; 32],
    },
}

impl MsgAddress {
    /// Parse an address from a string.
    ///
    /// Supported formats:
    /// - Raw: "workchain:hex_address" (e.g., "0:abc123...")
    /// - User-friendly base64: "EQ..." or "UQ..." (bounceable/non-bounceable)
    pub fn from_string(s: &str) -> CellResult<Self> {
        let s = s.trim();

        if s.is_empty() {
            return Ok(MsgAddress::Null);
        }

        // Check for raw format: "workchain:hex_address"
        if let Some(colon_pos) = s.find(':') {
            let workchain_str = &s[..colon_pos];
            let address_str = &s[colon_pos + 1..];

            let workchain: i32 = workchain_str
                .parse()
                .map_err(|_| CellError::InvalidAddress(format!("Invalid workchain: {}", workchain_str)))?;

            if address_str.len() != 64 {
                return Err(CellError::InvalidAddress(format!(
                    "Address hex must be 64 characters, got {}",
                    address_str.len()
                )));
            }

            let address_bytes = hex_decode(address_str)?;
            let mut address = [0u8; 32];
            address.copy_from_slice(&address_bytes);

            return Ok(MsgAddress::Internal { workchain, address });
        }

        // Check for user-friendly format (base64)
        if s.len() == 48 && (s.starts_with("EQ") || s.starts_with("UQ") || s.starts_with("Ef") || s.starts_with("kQ")) {
            return Self::from_user_friendly(s);
        }

        // Try to decode as base64 anyway
        if s.len() >= 36 && let Ok(addr) = Self::from_user_friendly(s) {
            return Ok(addr);
        }

        Err(CellError::InvalidAddress(format!("Unrecognized address format: {}", s)))
    }

    /// Parse a user-friendly address (base64 format).
    ///
    /// Format: 1 byte tag + 1 byte workchain + 32 bytes address + 2 bytes CRC16
    fn from_user_friendly(s: &str) -> CellResult<Self> {
        // Convert URL-safe base64 to standard base64
        let standard_b64: String = s
            .chars()
            .map(|c| match c {
                '-' => '+',
                '_' => '/',
                c => c,
            })
            .collect();

        let bytes = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &standard_b64)
            .map_err(|e| CellError::InvalidBase64(e.to_string()))?;

        if bytes.len() != 36 {
            return Err(CellError::InvalidAddress(format!(
                "User-friendly address must be 36 bytes, got {}",
                bytes.len()
            )));
        }

        // Verify CRC16
        let data = &bytes[0..34];
        let expected_crc = ((bytes[34] as u16) << 8) | (bytes[35] as u16);
        let actual_crc = crc16_xmodem(data);

        if expected_crc != actual_crc {
            return Err(CellError::InvalidAddress(format!(
                "CRC16 mismatch: expected {:04x}, got {:04x}",
                expected_crc, actual_crc
            )));
        }

        let _tag = bytes[0]; // Contains flags like bounceable, testnet
        let workchain = bytes[1] as i8 as i32;
        let mut address = [0u8; 32];
        address.copy_from_slice(&bytes[2..34]);

        Ok(MsgAddress::Internal { workchain, address })
    }

    /// Convert to raw string representation.
    ///
    /// Returns the raw format "workchain:hex_address" for internal addresses.
    pub fn to_raw_string(&self) -> String {
        match self {
            MsgAddress::Null => String::new(),
            MsgAddress::External { len, data } => {
                format!("extern:{}:{}", len, hex_encode(data))
            }
            MsgAddress::Internal { workchain, address } => {
                format!("{}:{}", workchain, hex_encode(address))
            }
        }
    }

    /// Convert to user-friendly format (base64).
    ///
    /// # Arguments
    /// * `bounceable` - If true, use bounceable address format
    /// * `testnet` - If true, mark as testnet address
    pub fn to_user_friendly(&self, bounceable: bool, testnet: bool) -> Option<String> {
        match self {
            MsgAddress::Internal { workchain, address } => {
                let mut data = Vec::with_capacity(36);

                // Tag byte
                let mut tag = if bounceable { 0x11 } else { 0x51 };
                if testnet {
                    tag |= 0x80;
                }
                data.push(tag);

                // Workchain (as signed byte)
                data.push(*workchain as i8 as u8);

                // Address
                data.extend_from_slice(address);

                // CRC16
                let crc = crc16_xmodem(&data);
                data.push((crc >> 8) as u8);
                data.push(crc as u8);

                // Encode as URL-safe base64
                let b64 = base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, &data);
                Some(b64)
            }
            _ => None,
        }
    }

    /// Get the workchain ID (if internal address).
    pub fn workchain(&self) -> Option<i32> {
        match self {
            MsgAddress::Internal { workchain, .. } => Some(*workchain),
            _ => None,
        }
    }

    /// Get the 256-bit address hash (if internal address).
    pub fn hash_part(&self) -> Option<&[u8; 32]> {
        match self {
            MsgAddress::Internal { address, .. } => Some(address),
            _ => None,
        }
    }

    /// Check if this is a null address.
    pub fn is_null(&self) -> bool {
        matches!(self, MsgAddress::Null)
    }

    /// Check if this is an external address.
    pub fn is_external(&self) -> bool {
        matches!(self, MsgAddress::External { .. })
    }

    /// Check if this is an internal address.
    pub fn is_internal(&self) -> bool {
        matches!(self, MsgAddress::Internal { .. })
    }

    /// Check if this is a masterchain address (workchain -1).
    pub fn is_masterchain(&self) -> bool {
        matches!(self, MsgAddress::Internal { workchain: -1, .. })
    }

    /// Check if this is a basechain address (workchain 0).
    pub fn is_basechain(&self) -> bool {
        matches!(self, MsgAddress::Internal { workchain: 0, .. })
    }
}

impl std::fmt::Display for MsgAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_raw_string())
    }
}


/// Decode hex string to bytes.
fn hex_decode(s: &str) -> CellResult<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return Err(CellError::InvalidAddress("Hex string must have even length".to_string()));
    }

    let mut result = Vec::with_capacity(s.len() / 2);
    for i in (0..s.len()).step_by(2) {
        let byte = u8::from_str_radix(&s[i..i + 2], 16)
            .map_err(|_| CellError::InvalidAddress(format!("Invalid hex: {}", &s[i..i + 2])))?;
        result.push(byte);
    }
    Ok(result)
}

/// Encode bytes to hex string.
fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// CRC16-XMODEM checksum.
fn crc16_xmodem(data: &[u8]) -> u16 {
    let mut crc: u16 = 0;
    for &byte in data {
        crc ^= (byte as u16) << 8;
        for _ in 0..8 {
            if crc & 0x8000 != 0 {
                crc = (crc << 1) ^ 0x1021;
            } else {
                crc <<= 1;
            }
        }
    }
    crc
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_null_address() {
        let addr = MsgAddress::Null;
        assert!(addr.is_null());
        assert!(!addr.is_internal());
        assert!(!addr.is_external());
        assert_eq!(addr.workchain(), None);
        assert_eq!(addr.hash_part(), None);
    }

    #[test]
    fn test_internal_address() {
        let addr = MsgAddress::Internal {
            workchain: 0,
            address: [0xAB; 32],
        };
        assert!(addr.is_internal());
        assert!(addr.is_basechain());
        assert!(!addr.is_masterchain());
        assert_eq!(addr.workchain(), Some(0));
        assert_eq!(addr.hash_part(), Some(&[0xAB; 32]));
    }

    #[test]
    fn test_masterchain_address() {
        let addr = MsgAddress::Internal {
            workchain: -1,
            address: [0x00; 32],
        };
        assert!(addr.is_masterchain());
        assert!(!addr.is_basechain());
    }

    #[test]
    fn test_from_raw_string() {
        let addr_str = "0:0000000000000000000000000000000000000000000000000000000000000000";
        let addr = MsgAddress::from_string(addr_str).unwrap();
        assert!(addr.is_internal());
        assert_eq!(addr.workchain(), Some(0));
        assert_eq!(addr.hash_part(), Some(&[0u8; 32]));
    }

    #[test]
    fn test_from_raw_string_masterchain() {
        let addr_str = "-1:0000000000000000000000000000000000000000000000000000000000000000";
        let addr = MsgAddress::from_string(addr_str).unwrap();
        assert!(addr.is_masterchain());
        assert_eq!(addr.workchain(), Some(-1));
    }

    #[test]
    fn test_to_string_roundtrip() {
        let addr = MsgAddress::Internal {
            workchain: 0,
            address: [0x12; 32],
        };
        let s = addr.to_string();
        let parsed = MsgAddress::from_string(&s).unwrap();
        assert_eq!(addr, parsed);
    }

    #[test]
    fn test_hex_encode_decode() {
        let original = vec![0x12, 0x34, 0xAB, 0xCD];
        let encoded = hex_encode(&original);
        assert_eq!(encoded, "1234abcd");
        let decoded = hex_decode(&encoded).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_crc16_xmodem() {
        // Test vector
        let data = b"123456789";
        let crc = crc16_xmodem(data);
        assert_eq!(crc, 0x31C3);
    }
}
