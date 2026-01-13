//! TON DNS record types.
//!
//! DNS records contain the resolved information for a domain. Each record type
//! has a specific TL-B schema and prefix:
//!
//! - `dns_smc_address#9fd3` - Smart contract address
//! - `dns_next_resolver#ba93` - Next resolver contract for iterative resolution
//! - `dns_adnl_address#ad01` - ADNL address for TON Sites
//! - `dns_storage_address#7473` - TON Storage bag ID
//!
//! # TL-B Schemas
//!
//! ```tlb
//! dns_smc_address#9fd3 smc_addr:MsgAddressInt flags:(## 8) { flags = 0 } = DNSRecord;
//! dns_next_resolver#ba93 resolver:MsgAddressInt = DNSRecord;
//! dns_adnl_address#ad01 adnl_addr:bits256 flags:(## 8) { flags <= 1 } proto_list:flags.0?ProtoList = DNSRecord;
//! dns_storage_address#7473 bag_id:bits256 = DNSRecord;
//! ```

use crate::error::{DnsError, DnsResult};

/// TL-B prefix for smart contract address record.
pub const PREFIX_SMC_ADDRESS: u16 = 0x9fd3;

/// TL-B prefix for next resolver record.
pub const PREFIX_NEXT_RESOLVER: u16 = 0xba93;

/// TL-B prefix for ADNL address record.
pub const PREFIX_ADNL_ADDRESS: u16 = 0xad01;

/// TL-B prefix for storage address record.
pub const PREFIX_STORAGE_ADDRESS: u16 = 0x7473;

/// TON workchain ID type.
pub type WorkchainId = i32;

/// A 256-bit address (account ID in a workchain).
pub type AccountId = [u8; 32];

/// An ADNL address (256-bit identifier).
pub type AdnlAddress = [u8; 32];

/// A TON Storage bag ID (256-bit identifier).
pub type BagId = [u8; 32];

/// A TON smart contract address (MsgAddressInt).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MsgAddressInt {
    /// The workchain ID (-1 for masterchain, 0 for basechain).
    pub workchain: WorkchainId,
    /// The 256-bit account address within the workchain.
    pub address: AccountId,
}

impl MsgAddressInt {
    /// Create a new address.
    pub fn new(workchain: WorkchainId, address: AccountId) -> Self {
        Self { workchain, address }
    }

    /// Create an address in the masterchain (workchain -1).
    pub fn masterchain(address: AccountId) -> Self {
        Self::new(-1, address)
    }

    /// Create an address in the basechain (workchain 0).
    pub fn basechain(address: AccountId) -> Self {
        Self::new(0, address)
    }

    /// Check if this is a masterchain address.
    pub fn is_masterchain(&self) -> bool {
        self.workchain == -1
    }

    /// Check if this is a basechain address.
    pub fn is_basechain(&self) -> bool {
        self.workchain == 0
    }

    /// Convert to raw string format (workchain:hex_address).
    pub fn to_raw_string(&self) -> String {
        format!("{}:{}", self.workchain, hex::encode(self.address))
    }

    /// Parse from raw string format (workchain:hex_address).
    pub fn from_raw_string(s: &str) -> DnsResult<Self> {
        let parts: Vec<&str> = s.split(':').collect();
        if parts.len() != 2 {
            return Err(DnsError::InvalidRecord(format!(
                "invalid address format: expected 'workchain:address', got '{}'",
                s
            )));
        }

        let workchain: WorkchainId = parts[0].parse().map_err(|_| {
            DnsError::InvalidRecord(format!("invalid workchain: {}", parts[0]))
        })?;

        let address_bytes = hex::decode(parts[1]).map_err(|_| {
            DnsError::InvalidRecord(format!("invalid address hex: {}", parts[1]))
        })?;

        if address_bytes.len() != 32 {
            return Err(DnsError::InvalidRecord(format!(
                "invalid address length: expected 32 bytes, got {}",
                address_bytes.len()
            )));
        }

        let mut address = [0u8; 32];
        address.copy_from_slice(&address_bytes);

        Ok(Self { workchain, address })
    }
}

impl std::fmt::Display for MsgAddressInt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_raw_string())
    }
}

/// Protocol types for ADNL address records.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    /// HTTP protocol.
    Http,
    /// HTTPS protocol.
    Https,
}

/// A DNS record containing resolved data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsRecord {
    /// Smart contract address record (prefix 0x9fd3).
    SmcAddress {
        /// The smart contract address.
        address: MsgAddressInt,
        /// Flags (currently must be 0).
        flags: u8,
    },

    /// Next resolver record (prefix 0xba93).
    NextResolver {
        /// Address of the next resolver contract.
        resolver: MsgAddressInt,
    },

    /// ADNL address record (prefix 0xad01) for TON Sites.
    AdnlAddress {
        /// The ADNL address.
        address: AdnlAddress,
        /// Flags (bit 0: has protocol list).
        flags: u8,
        /// Optional list of protocols (if flags bit 0 is set).
        protocols: Vec<Protocol>,
    },

    /// Storage address record (prefix 0x7473).
    StorageAddress {
        /// The TON Storage bag ID.
        bag_id: BagId,
    },

    /// Unknown record type.
    Unknown {
        /// The record prefix.
        prefix: u16,
        /// Raw data after the prefix.
        data: Vec<u8>,
    },
}

impl DnsRecord {
    /// Get the TL-B prefix for this record type.
    pub fn prefix(&self) -> u16 {
        match self {
            DnsRecord::SmcAddress { .. } => PREFIX_SMC_ADDRESS,
            DnsRecord::NextResolver { .. } => PREFIX_NEXT_RESOLVER,
            DnsRecord::AdnlAddress { .. } => PREFIX_ADNL_ADDRESS,
            DnsRecord::StorageAddress { .. } => PREFIX_STORAGE_ADDRESS,
            DnsRecord::Unknown { prefix, .. } => *prefix,
        }
    }

    /// Check if this is a next resolver record.
    pub fn is_next_resolver(&self) -> bool {
        matches!(self, DnsRecord::NextResolver { .. })
    }

    /// Check if this is a smart contract address record.
    pub fn is_smc_address(&self) -> bool {
        matches!(self, DnsRecord::SmcAddress { .. })
    }

    /// Check if this is an ADNL address record.
    pub fn is_adnl_address(&self) -> bool {
        matches!(self, DnsRecord::AdnlAddress { .. })
    }

    /// Check if this is a storage address record.
    pub fn is_storage_address(&self) -> bool {
        matches!(self, DnsRecord::StorageAddress { .. })
    }

    /// Get the next resolver address if this is a NextResolver record.
    pub fn as_next_resolver(&self) -> Option<&MsgAddressInt> {
        match self {
            DnsRecord::NextResolver { resolver } => Some(resolver),
            _ => None,
        }
    }

    /// Get the smart contract address if this is a SmcAddress record.
    pub fn as_smc_address(&self) -> Option<&MsgAddressInt> {
        match self {
            DnsRecord::SmcAddress { address, .. } => Some(address),
            _ => None,
        }
    }

    /// Get the ADNL address if this is an AdnlAddress record.
    pub fn as_adnl_address(&self) -> Option<&AdnlAddress> {
        match self {
            DnsRecord::AdnlAddress { address, .. } => Some(address),
            _ => None,
        }
    }

    /// Get the bag ID if this is a StorageAddress record.
    pub fn as_storage_address(&self) -> Option<&BagId> {
        match self {
            DnsRecord::StorageAddress { bag_id } => Some(bag_id),
            _ => None,
        }
    }

    /// Create a SmcAddress record.
    pub fn smc_address(address: MsgAddressInt) -> Self {
        DnsRecord::SmcAddress { address, flags: 0 }
    }

    /// Create a NextResolver record.
    pub fn next_resolver(resolver: MsgAddressInt) -> Self {
        DnsRecord::NextResolver { resolver }
    }

    /// Create an AdnlAddress record.
    pub fn adnl_address(address: AdnlAddress) -> Self {
        DnsRecord::AdnlAddress {
            address,
            flags: 0,
            protocols: Vec::new(),
        }
    }

    /// Create an AdnlAddress record with protocols.
    pub fn adnl_address_with_protocols(address: AdnlAddress, protocols: Vec<Protocol>) -> Self {
        let flags = if protocols.is_empty() { 0 } else { 1 };
        DnsRecord::AdnlAddress {
            address,
            flags,
            protocols,
        }
    }

    /// Create a StorageAddress record.
    pub fn storage_address(bag_id: BagId) -> Self {
        DnsRecord::StorageAddress { bag_id }
    }

    /// Serialize the record to bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut result = Vec::new();

        match self {
            DnsRecord::SmcAddress { address, flags } => {
                // Prefix
                result.extend_from_slice(&PREFIX_SMC_ADDRESS.to_be_bytes());
                // Workchain (1 byte for addr_std, 4 bytes for workchain in addr_std_full)
                // Simplified: use 1 byte workchain + 32 bytes address
                result.push(address.workchain as u8);
                result.extend_from_slice(&address.address);
                result.push(*flags);
            }
            DnsRecord::NextResolver { resolver } => {
                result.extend_from_slice(&PREFIX_NEXT_RESOLVER.to_be_bytes());
                result.push(resolver.workchain as u8);
                result.extend_from_slice(&resolver.address);
            }
            DnsRecord::AdnlAddress { address, flags, protocols } => {
                result.extend_from_slice(&PREFIX_ADNL_ADDRESS.to_be_bytes());
                result.extend_from_slice(address);
                result.push(*flags);
                if *flags & 1 != 0 {
                    result.push(protocols.len() as u8);
                    for proto in protocols {
                        match proto {
                            Protocol::Http => result.push(0),
                            Protocol::Https => result.push(1),
                        }
                    }
                }
            }
            DnsRecord::StorageAddress { bag_id } => {
                result.extend_from_slice(&PREFIX_STORAGE_ADDRESS.to_be_bytes());
                result.extend_from_slice(bag_id);
            }
            DnsRecord::Unknown { prefix, data } => {
                result.extend_from_slice(&prefix.to_be_bytes());
                result.extend_from_slice(data);
            }
        }

        result
    }

    /// Parse a record from bytes.
    pub fn from_bytes(data: &[u8]) -> DnsResult<Self> {
        if data.len() < 2 {
            return Err(DnsError::InvalidRecord("data too short for prefix".to_string()));
        }

        let prefix = u16::from_be_bytes([data[0], data[1]]);
        let data = &data[2..];

        match prefix {
            PREFIX_SMC_ADDRESS => {
                if data.len() < 34 {
                    return Err(DnsError::InvalidRecord(
                        "smc_address data too short".to_string(),
                    ));
                }
                let workchain = data[0] as i8 as i32;
                let mut address = [0u8; 32];
                address.copy_from_slice(&data[1..33]);
                let flags = data[33];
                Ok(DnsRecord::SmcAddress {
                    address: MsgAddressInt { workchain, address },
                    flags,
                })
            }
            PREFIX_NEXT_RESOLVER => {
                if data.len() < 33 {
                    return Err(DnsError::InvalidRecord(
                        "next_resolver data too short".to_string(),
                    ));
                }
                let workchain = data[0] as i8 as i32;
                let mut address = [0u8; 32];
                address.copy_from_slice(&data[1..33]);
                Ok(DnsRecord::NextResolver {
                    resolver: MsgAddressInt { workchain, address },
                })
            }
            PREFIX_ADNL_ADDRESS => {
                if data.len() < 33 {
                    return Err(DnsError::InvalidRecord(
                        "adnl_address data too short".to_string(),
                    ));
                }
                let mut address = [0u8; 32];
                address.copy_from_slice(&data[0..32]);
                let flags = data[32];
                let mut protocols = Vec::new();

                if flags & 1 != 0 && data.len() > 33 {
                    let proto_count = data[33] as usize;
                    for i in 0..proto_count {
                        if data.len() > 34 + i {
                            match data[34 + i] {
                                0 => protocols.push(Protocol::Http),
                                1 => protocols.push(Protocol::Https),
                                _ => {} // Unknown protocol, ignore
                            }
                        }
                    }
                }

                Ok(DnsRecord::AdnlAddress {
                    address,
                    flags,
                    protocols,
                })
            }
            PREFIX_STORAGE_ADDRESS => {
                if data.len() < 32 {
                    return Err(DnsError::InvalidRecord(
                        "storage_address data too short".to_string(),
                    ));
                }
                let mut bag_id = [0u8; 32];
                bag_id.copy_from_slice(&data[0..32]);
                Ok(DnsRecord::StorageAddress { bag_id })
            }
            _ => Ok(DnsRecord::Unknown {
                prefix,
                data: data.to_vec(),
            }),
        }
    }
}

/// A collection of DNS records for different categories.
#[derive(Debug, Clone, Default)]
pub struct DnsRecords {
    /// All records, keyed by category.
    records: Vec<(crate::categories::DnsCategory, DnsRecord)>,
}

impl DnsRecords {
    /// Create an empty record collection.
    pub fn new() -> Self {
        Self {
            records: Vec::new(),
        }
    }

    /// Add a record for a category.
    pub fn add(&mut self, category: crate::categories::DnsCategory, record: DnsRecord) {
        self.records.push((category, record));
    }

    /// Get all records.
    pub fn all(&self) -> &[(crate::categories::DnsCategory, DnsRecord)] {
        &self.records
    }

    /// Get the record for a specific category.
    pub fn get(&self, category: &crate::categories::DnsCategory) -> Option<&DnsRecord> {
        self.records
            .iter()
            .find(|(cat, _)| cat == category)
            .map(|(_, record)| record)
    }

    /// Get the wallet/smart contract address.
    pub fn wallet(&self) -> Option<&MsgAddressInt> {
        self.get(&crate::categories::DNS_CATEGORY_WALLET)
            .and_then(|r| r.as_smc_address())
    }

    /// Get the site ADNL address.
    pub fn site(&self) -> Option<&AdnlAddress> {
        self.get(&crate::categories::DNS_CATEGORY_SITE)
            .and_then(|r| r.as_adnl_address())
    }

    /// Get the storage bag ID.
    pub fn storage(&self) -> Option<&BagId> {
        self.get(&crate::categories::DNS_CATEGORY_STORAGE)
            .and_then(|r| r.as_storage_address())
    }

    /// Get the next resolver address.
    pub fn next_resolver(&self) -> Option<&MsgAddressInt> {
        self.get(&crate::categories::DNS_CATEGORY_NEXT_RESOLVER)
            .and_then(|r| r.as_next_resolver())
    }

    /// Check if the collection is empty.
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Get the number of records.
    pub fn len(&self) -> usize {
        self.records.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::categories::*;

    #[test]
    fn test_msg_address_int() {
        let addr = MsgAddressInt::masterchain([0x12; 32]);
        assert!(addr.is_masterchain());
        assert!(!addr.is_basechain());
        assert_eq!(addr.workchain, -1);

        let addr = MsgAddressInt::basechain([0x34; 32]);
        assert!(!addr.is_masterchain());
        assert!(addr.is_basechain());
        assert_eq!(addr.workchain, 0);
    }

    #[test]
    fn test_msg_address_raw_string() {
        let addr = MsgAddressInt::basechain([0xAB; 32]);
        let s = addr.to_raw_string();
        assert_eq!(s, format!("0:{}", "ab".repeat(32)));

        let parsed = MsgAddressInt::from_raw_string(&s).unwrap();
        assert_eq!(parsed, addr);
    }

    #[test]
    fn test_msg_address_masterchain_raw_string() {
        let addr = MsgAddressInt::masterchain([0xCD; 32]);
        let s = addr.to_raw_string();
        assert_eq!(s, format!("-1:{}", "cd".repeat(32)));

        let parsed = MsgAddressInt::from_raw_string(&s).unwrap();
        assert_eq!(parsed, addr);
    }

    #[test]
    fn test_dns_record_smc_address() {
        let addr = MsgAddressInt::basechain([0x12; 32]);
        let record = DnsRecord::smc_address(addr.clone());

        assert!(record.is_smc_address());
        assert!(!record.is_next_resolver());
        assert_eq!(record.prefix(), PREFIX_SMC_ADDRESS);
        assert_eq!(record.as_smc_address(), Some(&addr));
    }

    #[test]
    fn test_dns_record_next_resolver() {
        let resolver = MsgAddressInt::masterchain([0x34; 32]);
        let record = DnsRecord::next_resolver(resolver.clone());

        assert!(record.is_next_resolver());
        assert!(!record.is_smc_address());
        assert_eq!(record.prefix(), PREFIX_NEXT_RESOLVER);
        assert_eq!(record.as_next_resolver(), Some(&resolver));
    }

    #[test]
    fn test_dns_record_adnl_address() {
        let adnl = [0x56; 32];
        let record = DnsRecord::adnl_address(adnl);

        assert!(record.is_adnl_address());
        assert_eq!(record.prefix(), PREFIX_ADNL_ADDRESS);
        assert_eq!(record.as_adnl_address(), Some(&adnl));
    }

    #[test]
    fn test_dns_record_storage_address() {
        let bag_id = [0x78; 32];
        let record = DnsRecord::storage_address(bag_id);

        assert!(record.is_storage_address());
        assert_eq!(record.prefix(), PREFIX_STORAGE_ADDRESS);
        assert_eq!(record.as_storage_address(), Some(&bag_id));
    }

    #[test]
    fn test_dns_record_serialization() {
        // Test SmcAddress roundtrip
        let addr = MsgAddressInt::basechain([0x12; 32]);
        let record = DnsRecord::smc_address(addr);
        let bytes = record.to_bytes();
        let parsed = DnsRecord::from_bytes(&bytes).unwrap();
        assert_eq!(record, parsed);

        // Test NextResolver roundtrip
        let resolver = MsgAddressInt::masterchain([0x34; 32]);
        let record = DnsRecord::next_resolver(resolver);
        let bytes = record.to_bytes();
        let parsed = DnsRecord::from_bytes(&bytes).unwrap();
        assert_eq!(record, parsed);

        // Test AdnlAddress roundtrip
        let adnl = [0x56; 32];
        let record = DnsRecord::adnl_address(adnl);
        let bytes = record.to_bytes();
        let parsed = DnsRecord::from_bytes(&bytes).unwrap();
        assert_eq!(record, parsed);

        // Test StorageAddress roundtrip
        let bag_id = [0x78; 32];
        let record = DnsRecord::storage_address(bag_id);
        let bytes = record.to_bytes();
        let parsed = DnsRecord::from_bytes(&bytes).unwrap();
        assert_eq!(record, parsed);
    }

    #[test]
    fn test_dns_record_adnl_with_protocols() {
        let adnl = [0x99; 32];
        let protocols = vec![Protocol::Http, Protocol::Https];
        let record = DnsRecord::adnl_address_with_protocols(adnl, protocols.clone());

        match &record {
            DnsRecord::AdnlAddress { flags, protocols: protos, .. } => {
                assert_eq!(*flags, 1);
                assert_eq!(*protos, protocols);
            }
            _ => panic!("Expected AdnlAddress"),
        }

        let bytes = record.to_bytes();
        let parsed = DnsRecord::from_bytes(&bytes).unwrap();
        assert_eq!(record, parsed);
    }

    #[test]
    fn test_dns_records_collection() {
        let mut records = DnsRecords::new();
        assert!(records.is_empty());

        let wallet_addr = MsgAddressInt::basechain([0x11; 32]);
        records.add(DNS_CATEGORY_WALLET, DnsRecord::smc_address(wallet_addr.clone()));

        let site_adnl = [0x22; 32];
        records.add(DNS_CATEGORY_SITE, DnsRecord::adnl_address(site_adnl));

        assert!(!records.is_empty());
        assert_eq!(records.len(), 2);

        assert_eq!(records.wallet(), Some(&wallet_addr));
        assert_eq!(records.site(), Some(&site_adnl));
        assert!(records.storage().is_none());
    }

    #[test]
    fn test_unknown_record() {
        let data = vec![0xFF, 0xEE, 0x01, 0x02, 0x03];
        let record = DnsRecord::from_bytes(&data).unwrap();

        match record {
            DnsRecord::Unknown { prefix, data } => {
                assert_eq!(prefix, 0xFFEE);
                assert_eq!(data, vec![0x01, 0x02, 0x03]);
            }
            _ => panic!("Expected Unknown record"),
        }
    }

    #[test]
    fn test_invalid_record_data() {
        // Too short
        let result = DnsRecord::from_bytes(&[0x9f]);
        assert!(result.is_err());

        // SmcAddress with insufficient data
        let mut data = PREFIX_SMC_ADDRESS.to_be_bytes().to_vec();
        data.extend_from_slice(&[0; 10]); // Not enough data
        let result = DnsRecord::from_bytes(&data);
        assert!(result.is_err());
    }
}
