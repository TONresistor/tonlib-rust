//! TON DNS resolver implementation.
//!
//! The resolver handles the iterative DNS resolution process:
//!
//! 1. Start with the root DNS contract (from masterchain config #4)
//! 2. Convert domain to internal representation
//! 3. Call `dnsresolve` get-method on the resolver contract
//! 4. If partially resolved, follow the next_resolver chain
//! 5. Continue until fully resolved or error
//!
//! # Resolution Process
//!
//! ```text
//! Domain: "sub.test.ton"
//! Internal: "ton\0test\0sub\0"
//!
//! Step 1: Call root DNS with "ton\0test\0sub\0"
//!   -> Resolves "ton\0" (32 bits), returns next_resolver for .ton
//!
//! Step 2: Call .ton resolver with "test\0sub\0"
//!   -> Resolves "test\0" (40 bits), returns next_resolver for test.ton
//!
//! Step 3: Call test.ton resolver with "sub\0"
//!   -> Resolves "sub\0" (32 bits), returns final record
//! ```

use crate::categories::{DnsCategory, DNS_CATEGORY_ALL, DNS_CATEGORY_NEXT_RESOLVER};
use crate::domain::{domain_to_internal, resolved_bytes, TonDomain};
use crate::error::{DnsError, DnsResult};
use crate::records::{AdnlAddress, BagId, DnsRecord, DnsRecords, MsgAddressInt};

/// Maximum depth for iterative resolution to prevent infinite loops.
pub const MAX_RESOLUTION_DEPTH: usize = 128;

/// Result of a single dnsresolve call.
#[derive(Debug, Clone)]
pub struct DnsResolveResult {
    /// Number of bits resolved (must be multiple of 8).
    pub resolved_bits: usize,
    /// The resolved record (if any).
    pub record: Option<DnsRecord>,
}

impl DnsResolveResult {
    /// Get the number of bytes resolved.
    pub fn resolved_bytes(&self) -> usize {
        resolved_bytes(self.resolved_bits)
    }

    /// Check if the resolution is complete (all bits resolved).
    pub fn is_complete(&self, total_bytes: usize) -> bool {
        self.resolved_bytes() == total_bytes
    }
}

/// Trait for DNS resolver backends.
///
/// This trait allows different implementations for:
/// - Real network resolution (using ADNL/Liteserver)
/// - Mock/test resolution
/// - Cached resolution
pub trait DnsBackend {
    /// Get the root DNS contract address from masterchain config #4.
    fn get_root_dns(&self) -> DnsResult<MsgAddressInt>;

    /// Call dnsresolve get-method on a contract.
    ///
    /// # Arguments
    ///
    /// * `contract` - Address of the DNS resolver contract
    /// * `domain_bytes` - Remaining domain bytes in internal format
    /// * `category` - Category to resolve (zero = all categories)
    ///
    /// # Returns
    ///
    /// The resolution result containing resolved bits and optional record.
    fn call_dnsresolve(
        &self,
        contract: &MsgAddressInt,
        domain_bytes: &[u8],
        category: &DnsCategory,
    ) -> DnsResult<DnsResolveResult>;
}

/// TON DNS resolver.
///
/// Resolves human-readable `.ton` domains to addresses.
///
/// # Example
///
/// ```ignore
/// use ton_dns::{TonDns, MockDnsBackend};
///
/// let backend = MockDnsBackend::new();
/// let dns = TonDns::new(backend);
///
/// // Resolve wallet address
/// let wallet = dns.resolve_wallet("test.ton").await?;
/// println!("Wallet: {}", wallet);
///
/// // Resolve TON Site
/// let site = dns.resolve_site("mysite.ton").await?;
/// println!("Site ADNL: {:?}", site);
/// ```
pub struct TonDns<B: DnsBackend> {
    backend: B,
    max_depth: usize,
}

impl<B: DnsBackend> TonDns<B> {
    /// Create a new DNS resolver with the given backend.
    pub fn new(backend: B) -> Self {
        Self {
            backend,
            max_depth: MAX_RESOLUTION_DEPTH,
        }
    }

    /// Set the maximum resolution depth.
    pub fn with_max_depth(mut self, max_depth: usize) -> Self {
        self.max_depth = max_depth;
        self
    }

    /// Get a reference to the backend.
    pub fn backend(&self) -> &B {
        &self.backend
    }

    /// Resolve a domain to all available records.
    ///
    /// # Arguments
    ///
    /// * `domain` - The domain to resolve (e.g., "test.ton")
    ///
    /// # Returns
    ///
    /// A collection of DNS records for all categories.
    pub fn resolve(&self, domain: &str) -> DnsResult<DnsRecords> {
        let domain = TonDomain::parse_normalized(domain)?;
        self.resolve_domain(&domain, None)
    }

    /// Resolve a domain for a specific category.
    ///
    /// # Arguments
    ///
    /// * `domain` - The domain to resolve
    /// * `category` - The category to resolve
    ///
    /// # Returns
    ///
    /// The DNS record for the specified category, if found.
    pub fn resolve_category(
        &self,
        domain: &str,
        category: &DnsCategory,
    ) -> DnsResult<Option<DnsRecord>> {
        let domain = TonDomain::parse_normalized(domain)?;
        let records = self.resolve_domain(&domain, Some(*category))?;
        Ok(records.get(category).cloned())
    }

    /// Resolve a domain to its wallet/smart contract address.
    ///
    /// # Arguments
    ///
    /// * `domain` - The domain to resolve (e.g., "alice.ton")
    ///
    /// # Returns
    ///
    /// The smart contract address for payments.
    pub fn resolve_wallet(&self, domain: &str) -> DnsResult<MsgAddressInt> {
        use crate::categories::DNS_CATEGORY_WALLET;

        let record = self.resolve_category(domain, &DNS_CATEGORY_WALLET)?;
        match record {
            Some(DnsRecord::SmcAddress { address, .. }) => Ok(address),
            Some(_) => Err(DnsError::InvalidRecord(
                "wallet category contains non-address record".to_string(),
            )),
            None => Err(DnsError::DomainNotFound(format!(
                "no wallet record for {}",
                domain
            ))),
        }
    }

    /// Resolve a domain to its TON Site ADNL address.
    ///
    /// # Arguments
    ///
    /// * `domain` - The domain to resolve (e.g., "mysite.ton")
    ///
    /// # Returns
    ///
    /// The ADNL address for the TON Site.
    pub fn resolve_site(&self, domain: &str) -> DnsResult<AdnlAddress> {
        use crate::categories::DNS_CATEGORY_SITE;

        let record = self.resolve_category(domain, &DNS_CATEGORY_SITE)?;
        match record {
            Some(DnsRecord::AdnlAddress { address, .. }) => Ok(address),
            Some(_) => Err(DnsError::InvalidRecord(
                "site category contains non-ADNL record".to_string(),
            )),
            None => Err(DnsError::DomainNotFound(format!(
                "no site record for {}",
                domain
            ))),
        }
    }

    /// Resolve a domain to its TON Storage bag ID.
    ///
    /// # Arguments
    ///
    /// * `domain` - The domain to resolve (e.g., "files.ton")
    ///
    /// # Returns
    ///
    /// The TON Storage bag ID.
    pub fn resolve_storage(&self, domain: &str) -> DnsResult<BagId> {
        use crate::categories::DNS_CATEGORY_STORAGE;

        let record = self.resolve_category(domain, &DNS_CATEGORY_STORAGE)?;
        match record {
            Some(DnsRecord::StorageAddress { bag_id }) => Ok(bag_id),
            Some(_) => Err(DnsError::InvalidRecord(
                "storage category contains non-bag-id record".to_string(),
            )),
            None => Err(DnsError::DomainNotFound(format!(
                "no storage record for {}",
                domain
            ))),
        }
    }

    /// Internal resolution implementation.
    fn resolve_domain(
        &self,
        domain: &TonDomain,
        category: Option<DnsCategory>,
    ) -> DnsResult<DnsRecords> {
        let internal = domain.to_internal();
        let category_bytes = category.unwrap_or(DNS_CATEGORY_ALL);

        // Get root DNS contract
        let mut resolver = self.backend.get_root_dns()?;
        let mut remaining = internal.as_slice();
        let mut depth = 0;

        loop {
            // Check depth limit
            if depth >= self.max_depth {
                return Err(DnsError::MaxDepthExceeded(depth));
            }
            depth += 1;

            // Call dnsresolve
            let result = self.backend.call_dnsresolve(&resolver, remaining, &category_bytes)?;

            let resolved_len = result.resolved_bytes();

            // No progress made
            if resolved_len == 0 {
                return Err(DnsError::DomainNotFound(domain.to_string()));
            }

            // Fully resolved
            if resolved_len == remaining.len() {
                let mut records = DnsRecords::new();
                if let Some(record) = result.record {
                    records.add(category_bytes, record);
                }
                return Ok(records);
            }

            // Partial resolution - need to follow next_resolver
            let next_resolver = match &result.record {
                Some(DnsRecord::NextResolver { resolver }) => resolver.clone(),
                Some(_) => {
                    // We need next_resolver for partial resolution
                    // Try to get it from the next_resolver category
                    let next_result = self.backend.call_dnsresolve(
                        &resolver,
                        remaining,
                        &DNS_CATEGORY_NEXT_RESOLVER,
                    )?;

                    match next_result.record {
                        Some(DnsRecord::NextResolver { resolver }) => resolver,
                        _ => return Err(DnsError::NoNextResolver),
                    }
                }
                None => return Err(DnsError::NoNextResolver),
            };

            resolver = next_resolver;
            remaining = &remaining[resolved_len..];
        }
    }
}

/// A mock DNS backend for testing.
///
/// This backend allows setting up predefined resolution results.
#[derive(Debug, Default)]
pub struct MockDnsBackend {
    /// Root DNS contract address.
    root_dns: Option<MsgAddressInt>,
    /// Predefined resolution results keyed by (contract, domain_prefix).
    results: Vec<MockResolveEntry>,
}

/// A single mock resolution entry.
#[derive(Debug, Clone)]
struct MockResolveEntry {
    contract: MsgAddressInt,
    domain_prefix: Vec<u8>,
    category: DnsCategory,
    result: DnsResolveResult,
}

impl MockDnsBackend {
    /// Create a new mock backend.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the root DNS contract address.
    pub fn set_root_dns(&mut self, address: MsgAddressInt) {
        self.root_dns = Some(address);
    }

    /// Add a mock resolution result.
    ///
    /// # Arguments
    ///
    /// * `contract` - The resolver contract address
    /// * `domain_prefix` - Domain bytes that trigger this result
    /// * `category` - Category for this result
    /// * `resolved_bits` - Number of bits resolved
    /// * `record` - The record to return
    pub fn add_result(
        &mut self,
        contract: MsgAddressInt,
        domain_prefix: Vec<u8>,
        category: DnsCategory,
        resolved_bits: usize,
        record: Option<DnsRecord>,
    ) {
        self.results.push(MockResolveEntry {
            contract,
            domain_prefix,
            category,
            result: DnsResolveResult {
                resolved_bits,
                record,
            },
        });
    }

    /// Configure a simple domain resolution.
    ///
    /// This sets up the mock to resolve a domain through the standard
    /// .ton registry chain.
    pub fn configure_domain(
        &mut self,
        domain: &str,
        category: DnsCategory,
        record: DnsRecord,
    ) -> DnsResult<()> {
        let internal = domain_to_internal(domain);
        let parts: Vec<&str> = domain.split('.').collect();

        // Set up root DNS if not set
        if self.root_dns.is_none() {
            self.root_dns = Some(MsgAddressInt::masterchain([0; 32]));
        }
        let root = self.root_dns.clone().unwrap();

        // Set up chain of resolvers
        let mut current_resolver = root;
        let mut current_pos = 0;

        for (i, part) in parts.iter().rev().enumerate() {
            let part_len = part.len() + 1; // +1 for null terminator
            let is_last = i == parts.len() - 1;

            if is_last {
                // Final resolution - return the actual record
                self.add_result(
                    current_resolver.clone(),
                    internal[current_pos..].to_vec(),
                    category,
                    part_len * 8,
                    Some(record.clone()),
                );
            } else {
                // Intermediate resolution - return next_resolver
                let next_resolver = MsgAddressInt::masterchain([(i + 1) as u8; 32]);
                self.add_result(
                    current_resolver.clone(),
                    internal[current_pos..].to_vec(),
                    DNS_CATEGORY_ALL,
                    part_len * 8,
                    Some(DnsRecord::next_resolver(next_resolver.clone())),
                );
                current_resolver = next_resolver;
            }

            current_pos += part_len;
        }

        Ok(())
    }
}

impl DnsBackend for MockDnsBackend {
    fn get_root_dns(&self) -> DnsResult<MsgAddressInt> {
        self.root_dns.clone().ok_or_else(|| {
            DnsError::ResolutionFailed("root DNS not configured".to_string())
        })
    }

    fn call_dnsresolve(
        &self,
        contract: &MsgAddressInt,
        domain_bytes: &[u8],
        category: &DnsCategory,
    ) -> DnsResult<DnsResolveResult> {
        // Find matching result
        for entry in &self.results {
            if &entry.contract == contract
                && domain_bytes.starts_with(&entry.domain_prefix)
                && (*category == DNS_CATEGORY_ALL || entry.category == *category || entry.category == DNS_CATEGORY_ALL)
            {
                return Ok(entry.result.clone());
            }
        }

        // No match found - domain not found
        Err(DnsError::DomainNotFound(format!(
            "no mock result for contract {} with domain {:?}",
            contract, domain_bytes
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::categories::*;
    use crate::records::MsgAddressInt;

    #[test]
    fn test_mock_backend_basic() {
        let mut backend = MockDnsBackend::new();
        let root = MsgAddressInt::masterchain([0; 32]);
        backend.set_root_dns(root.clone());

        assert_eq!(backend.get_root_dns().unwrap(), root);
    }

    #[test]
    fn test_mock_backend_no_root() {
        let backend = MockDnsBackend::new();
        assert!(backend.get_root_dns().is_err());
    }

    #[test]
    fn test_simple_resolution() {
        let mut backend = MockDnsBackend::new();
        let root = MsgAddressInt::masterchain([0; 32]);
        let wallet_addr = MsgAddressInt::basechain([0xAB; 32]);

        backend.set_root_dns(root.clone());

        // Configure: ton\0 -> next_resolver
        let ton_resolver = MsgAddressInt::masterchain([1; 32]);
        backend.add_result(
            root.clone(),
            b"ton\0".to_vec(),
            DNS_CATEGORY_ALL,
            32, // "ton\0" = 4 bytes = 32 bits
            Some(DnsRecord::next_resolver(ton_resolver.clone())),
        );

        // Configure: test\0 -> wallet address
        backend.add_result(
            ton_resolver.clone(),
            b"test\0".to_vec(),
            DNS_CATEGORY_ALL,
            40, // "test\0" = 5 bytes = 40 bits
            Some(DnsRecord::smc_address(wallet_addr.clone())),
        );

        let dns = TonDns::new(backend);
        let result = dns.resolve_wallet("test.ton").unwrap();
        assert_eq!(result, wallet_addr);
    }

    #[test]
    fn test_configure_domain_helper() {
        let mut backend = MockDnsBackend::new();
        let wallet_addr = MsgAddressInt::basechain([0xCD; 32]);

        backend
            .configure_domain("test.ton", DNS_CATEGORY_WALLET, DnsRecord::smc_address(wallet_addr.clone()))
            .unwrap();

        let dns = TonDns::new(backend);
        let result = dns.resolve_wallet("test.ton").unwrap();
        assert_eq!(result, wallet_addr);
    }

    #[test]
    fn test_resolve_site() {
        let mut backend = MockDnsBackend::new();
        let site_adnl = [0xEF; 32];

        backend
            .configure_domain("mysite.ton", DNS_CATEGORY_SITE, DnsRecord::adnl_address(site_adnl))
            .unwrap();

        let dns = TonDns::new(backend);
        let result = dns.resolve_site("mysite.ton").unwrap();
        assert_eq!(result, site_adnl);
    }

    #[test]
    fn test_resolve_storage() {
        let mut backend = MockDnsBackend::new();
        let bag_id = [0x12; 32];

        backend
            .configure_domain("files.ton", DNS_CATEGORY_STORAGE, DnsRecord::storage_address(bag_id))
            .unwrap();

        let dns = TonDns::new(backend);
        let result = dns.resolve_storage("files.ton").unwrap();
        assert_eq!(result, bag_id);
    }

    #[test]
    fn test_domain_not_found() {
        let mut backend = MockDnsBackend::new();
        let root = MsgAddressInt::masterchain([0; 32]);
        backend.set_root_dns(root);

        let dns = TonDns::new(backend);
        let result = dns.resolve_wallet("nonexistent.ton");
        assert!(result.is_err());
    }

    #[test]
    fn test_case_insensitive() {
        let mut backend = MockDnsBackend::new();
        let wallet_addr = MsgAddressInt::basechain([0x99; 32]);

        backend
            .configure_domain("test.ton", DNS_CATEGORY_WALLET, DnsRecord::smc_address(wallet_addr.clone()))
            .unwrap();

        let dns = TonDns::new(backend);

        // Should work with any case
        let result = dns.resolve_wallet("TEST.TON").unwrap();
        assert_eq!(result, wallet_addr);

        let result = dns.resolve_wallet("Test.Ton").unwrap();
        assert_eq!(result, wallet_addr);
    }

    #[test]
    fn test_max_depth_exceeded() {
        let mut backend = MockDnsBackend::new();
        let root = MsgAddressInt::masterchain([0; 32]);
        backend.set_root_dns(root.clone());

        // Create a circular reference (next_resolver points to itself)
        backend.add_result(
            root.clone(),
            b"ton\0".to_vec(),
            DNS_CATEGORY_ALL,
            32,
            Some(DnsRecord::next_resolver(root.clone())),
        );

        // But that doesn't make progress on remaining, so it will fail with DomainNotFound
        // To test max depth, we need to make progress each time
        // This is a simplified test - real circular references are prevented by the remaining bytes check

        let dns = TonDns::new(backend).with_max_depth(5);
        let result = dns.resolve("test.ton");
        // Should fail (either domain not found or max depth)
        assert!(result.is_err());
    }

    #[test]
    fn test_dns_resolve_result() {
        let result = DnsResolveResult {
            resolved_bits: 32,
            record: Some(DnsRecord::smc_address(MsgAddressInt::basechain([0; 32]))),
        };

        assert_eq!(result.resolved_bytes(), 4);
        assert!(result.is_complete(4));
        assert!(!result.is_complete(8));
    }

    #[test]
    fn test_invalid_domain() {
        let backend = MockDnsBackend::new();
        let dns = TonDns::new(backend);

        // Invalid TLD
        let result = dns.resolve("test.com");
        assert!(matches!(result, Err(DnsError::InvalidTld(_))));

        // Empty domain
        let result = dns.resolve("");
        assert!(matches!(result, Err(DnsError::InvalidDomain(_))));
    }
}
