//! TON DNS Library
//!
//! This crate provides TON DNS resolution functionality, translating human-readable
//! `.ton` domains to various types of addresses (smart contracts, ADNL, storage, etc.).
//!
//! # Overview
//!
//! TON DNS is a decentralized domain name system built on the TON blockchain.
//! It allows mapping human-readable names like `alice.ton` to:
//!
//! - **Wallet addresses**: Smart contract addresses for payments
//! - **ADNL addresses**: For TON Sites and services
//! - **Storage addresses**: TON Storage bag IDs
//!
//! # Domain Format
//!
//! - Domains must end with `.ton`
//! - UTF-8 encoded, max 126 bytes per component
//! - Control characters (bytes 0-32) are prohibited
//! - Case-sensitive internally, but applications typically normalize to lowercase
//!
//! # Resolution Process
//!
//! DNS resolution is iterative:
//!
//! 1. Start with the root DNS contract (masterchain config #4)
//! 2. Convert domain to internal representation (reversed, null-terminated)
//! 3. Call `dnsresolve` get-method on each resolver in the chain
//! 4. Follow `next_resolver` records until fully resolved
//!
//! # Example
//!
//! ```
//! use ton_dns::{TonDns, MockDnsBackend, DnsRecord, MsgAddressInt};
//! use ton_dns::categories::DNS_CATEGORY_WALLET;
//!
//! // Create a mock backend for testing
//! let mut backend = MockDnsBackend::new();
//! let wallet_addr = MsgAddressInt::basechain([0xAB; 32]);
//!
//! backend.configure_domain(
//!     "alice.ton",
//!     DNS_CATEGORY_WALLET,
//!     DnsRecord::smc_address(wallet_addr.clone()),
//! ).unwrap();
//!
//! // Create resolver and resolve
//! let dns = TonDns::new(backend);
//! let result = dns.resolve_wallet("alice.ton").unwrap();
//! assert_eq!(result, wallet_addr);
//! ```
//!
//! # Record Types
//!
//! DNS records use TL-B prefixes to identify their type:
//!
//! | Prefix | Type | Description |
//! |--------|------|-------------|
//! | 0x9fd3 | `dns_smc_address` | Smart contract address |
//! | 0xba93 | `dns_next_resolver` | Next resolver in chain |
//! | 0xad01 | `dns_adnl_address` | ADNL address for TON Sites |
//! | 0x7473 | `dns_storage_address` | TON Storage bag ID |
//!
//! # Categories
//!
//! Records are organized by category, identified by SHA256 hashes:
//!
//! - `wallet` - Payment address
//! - `site` - TON Site ADNL address
//! - `storage` - TON Storage bag ID
//! - `dns_next_resolver` - Next resolver contract
//!
//! # References
//!
//! - [TEP-81: TON DNS Standard](https://github.com/ton-blockchain/TEPs/blob/master/text/0081-dns-standard.md)
//! - [DNS Contract](https://github.com/ton-blockchain/dns-contract)

pub mod categories;
pub mod domain;
pub mod error;
pub mod records;
pub mod resolver;

#[cfg(feature = "lite-client")]
pub mod lite_backend;

// Re-export main types for convenience
pub use categories::{
    category_from_name, category_name, is_all_categories, DnsCategory, DNS_CATEGORY_ALL,
    DNS_CATEGORY_NEXT_RESOLVER, DNS_CATEGORY_SITE, DNS_CATEGORY_STORAGE, DNS_CATEGORY_WALLET,
};

pub use domain::{
    domain_to_internal, internal_to_domain, resolved_bytes, TonDomain, MAX_COMPONENT_LENGTH,
    TON_TLD,
};

pub use error::{DnsError, DnsResult};

pub use records::{
    AdnlAddress, BagId, DnsRecord, DnsRecords, MsgAddressInt, Protocol, WorkchainId,
    PREFIX_ADNL_ADDRESS, PREFIX_NEXT_RESOLVER, PREFIX_SMC_ADDRESS, PREFIX_STORAGE_ADDRESS,
};

pub use resolver::{
    DnsBackend, DnsResolveResult, MockDnsBackend, TonDns, MAX_RESOLUTION_DEPTH,
};

#[cfg(feature = "lite-client")]
pub use lite_backend::{LiteClientBackend, parse_dns_record_from_cell};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_full_resolution_flow() {
        // Create mock backend
        let mut backend = MockDnsBackend::new();

        // Configure wallet address for alice.ton
        let alice_wallet = MsgAddressInt::basechain([0x11; 32]);
        backend
            .configure_domain(
                "alice.ton",
                DNS_CATEGORY_WALLET,
                DnsRecord::smc_address(alice_wallet.clone()),
            )
            .unwrap();

        // Configure site for mysite.ton
        let site_adnl = [0x22; 32];
        backend
            .configure_domain("mysite.ton", DNS_CATEGORY_SITE, DnsRecord::adnl_address(site_adnl))
            .unwrap();

        // Configure storage for files.ton
        let bag_id = [0x33; 32];
        backend
            .configure_domain(
                "files.ton",
                DNS_CATEGORY_STORAGE,
                DnsRecord::storage_address(bag_id),
            )
            .unwrap();

        // Create resolver
        let dns = TonDns::new(backend);

        // Test wallet resolution
        let wallet = dns.resolve_wallet("alice.ton").unwrap();
        assert_eq!(wallet, alice_wallet);

        // Test site resolution
        let site = dns.resolve_site("mysite.ton").unwrap();
        assert_eq!(site, site_adnl);

        // Test storage resolution
        let storage = dns.resolve_storage("files.ton").unwrap();
        assert_eq!(storage, bag_id);
    }

    #[test]
    fn test_domain_validation() {
        // Valid domains
        assert!(TonDomain::parse("test.ton").is_ok());
        assert!(TonDomain::parse("sub.test.ton").is_ok());
        assert!(TonDomain::parse("a.b.c.d.ton").is_ok());

        // Invalid domains
        assert!(TonDomain::parse("").is_err());
        assert!(TonDomain::parse("test").is_err());
        assert!(TonDomain::parse("test.com").is_err());
        assert!(TonDomain::parse(".ton").is_err());
        assert!(TonDomain::parse("test..ton").is_err());
    }

    #[test]
    fn test_domain_internal_representation() {
        assert_eq!(domain_to_internal("test.ton"), b"ton\0test\0");
        assert_eq!(domain_to_internal("sub.test.ton"), b"ton\0test\0sub\0");

        // Roundtrip
        let domain = "alice.ton";
        let internal = domain_to_internal(domain);
        let recovered = internal_to_domain(&internal).unwrap();
        assert_eq!(recovered, domain);
    }

    #[test]
    fn test_categories() {
        // Categories should be SHA256 of their names
        use ton_crypto::sha256;

        assert_eq!(DNS_CATEGORY_WALLET, sha256(b"wallet"));
        assert_eq!(DNS_CATEGORY_SITE, sha256(b"site"));
        assert_eq!(DNS_CATEGORY_STORAGE, sha256(b"storage"));
        assert_eq!(DNS_CATEGORY_NEXT_RESOLVER, sha256(b"dns_next_resolver"));

        // Runtime computation should match
        assert_eq!(category_from_name("wallet"), DNS_CATEGORY_WALLET);
        assert_eq!(category_from_name("site"), DNS_CATEGORY_SITE);
    }

    #[test]
    fn test_record_types() {
        // SmcAddress
        let addr = MsgAddressInt::basechain([0xAA; 32]);
        let record = DnsRecord::smc_address(addr.clone());
        assert_eq!(record.prefix(), PREFIX_SMC_ADDRESS);
        assert_eq!(record.as_smc_address(), Some(&addr));

        // NextResolver
        let resolver = MsgAddressInt::masterchain([0xBB; 32]);
        let record = DnsRecord::next_resolver(resolver.clone());
        assert_eq!(record.prefix(), PREFIX_NEXT_RESOLVER);
        assert_eq!(record.as_next_resolver(), Some(&resolver));

        // AdnlAddress
        let adnl = [0xCC; 32];
        let record = DnsRecord::adnl_address(adnl);
        assert_eq!(record.prefix(), PREFIX_ADNL_ADDRESS);
        assert_eq!(record.as_adnl_address(), Some(&adnl));

        // StorageAddress
        let bag = [0xDD; 32];
        let record = DnsRecord::storage_address(bag);
        assert_eq!(record.prefix(), PREFIX_STORAGE_ADDRESS);
        assert_eq!(record.as_storage_address(), Some(&bag));
    }

    #[test]
    fn test_address_formats() {
        // Masterchain address
        let addr = MsgAddressInt::masterchain([0x12; 32]);
        assert!(addr.is_masterchain());
        assert_eq!(addr.workchain, -1);

        // Basechain address
        let addr = MsgAddressInt::basechain([0x34; 32]);
        assert!(addr.is_basechain());
        assert_eq!(addr.workchain, 0);

        // Raw string format
        let addr = MsgAddressInt::basechain([0xAB; 32]);
        let s = addr.to_raw_string();
        let parsed = MsgAddressInt::from_raw_string(&s).unwrap();
        assert_eq!(parsed, addr);
    }

    #[test]
    fn test_case_normalization() {
        // parse_normalized should convert to lowercase
        let domain = TonDomain::parse_normalized("TEST.TON").unwrap();
        assert_eq!(domain.as_str(), "test.ton");

        let domain = TonDomain::parse_normalized("Alice.Ton").unwrap();
        assert_eq!(domain.as_str(), "alice.ton");
    }
}
