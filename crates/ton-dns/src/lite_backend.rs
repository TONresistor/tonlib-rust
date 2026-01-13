//! LiteClient backend for real TON DNS resolution.
//!
//! This module provides a DNS backend that queries TON DNS smart contracts
//! through a liteserver connection. It implements the full DNS resolution flow:
//!
//! 1. Get root DNS contract address from masterchain config param #4
//! 2. Convert domain to internal format ("test.ton" -> "ton\0test\0")
//! 3. Call `dnsresolve` get method on the contract
//! 4. Parse result: (resolved_bits, Cell containing record)
//! 5. If partial resolution, follow next_resolver chain
//!
//! # Example
//!
//! ```rust,no_run
//! use std::sync::Arc;
//! use ton_dns::{TonDns, LiteClientBackend};
//! use ton_adnl::LiteClient;
//!
//! async fn example() -> Result<(), Box<dyn std::error::Error>> {
//!     // Connect to a liteserver
//!     let client = Arc::new(LiteClient::connect("1.2.3.4", 12345, &[0u8; 32]).await?);
//!
//!     // Create DNS resolver with lite client backend
//!     let backend = LiteClientBackend::new(client);
//!     let dns = TonDns::new(backend);
//!
//!     // Resolve a .ton domain
//!     let wallet = dns.resolve_wallet("foundation.ton")?;
//!     println!("Foundation wallet: {}", wallet);
//!
//!     Ok(())
//! }
//! ```

use std::sync::Arc;

use tokio::sync::Mutex;
use ton_adnl::{AccountAddress, ConfigInfo, LiteClient, RunMethodResult};
use ton_cell::{BagOfCells, Cell, CellBuilder, CellSlice, MsgAddress};

use crate::categories::{DnsCategory, DNS_CATEGORY_ALL};
use crate::domain::domain_to_internal;
use crate::error::{DnsError, DnsResult};
use crate::records::{DnsRecord, MsgAddressInt, Protocol};
use crate::resolver::{DnsBackend, DnsResolveResult};

/// LiteClient backend for DNS resolution.
///
/// This backend connects to a TON liteserver and queries DNS smart contracts
/// to resolve domain names.
pub struct LiteClientBackend {
    /// The LiteClient connection.
    client: Arc<LiteClient>,
    /// Cached root DNS contract address.
    root_dns: Mutex<Option<MsgAddressInt>>,
}

impl LiteClientBackend {
    /// Create a new LiteClientBackend with the given client.
    ///
    /// # Arguments
    ///
    /// * `client` - An Arc-wrapped LiteClient connection.
    pub fn new(client: Arc<LiteClient>) -> Self {
        Self {
            client,
            root_dns: Mutex::new(None),
        }
    }

    /// Get the root DNS contract address from masterchain config param #4.
    ///
    /// This method caches the result to avoid repeated queries.
    pub async fn get_root_dns_async(&self) -> DnsResult<MsgAddressInt> {
        // Check cache first
        {
            let cached = self.root_dns.lock().await;
            if let Some(addr) = cached.as_ref() {
                return Ok(addr.clone());
            }
        }

        // Fetch from blockchain
        let mc_info = self
            .client
            .get_masterchain_info()
            .await
            .map_err(|e| DnsError::ResolutionFailed(format!("Failed to get masterchain info: {}", e)))?;

        let config = self
            .client
            .get_config_params(&mc_info.last, 0, &[4])
            .await
            .map_err(|e| DnsError::ResolutionFailed(format!("Failed to get config param #4: {}", e)))?;

        // Parse config proof to extract DNS root address
        let addr = parse_config_param_4(&config)?;

        // Cache the result
        {
            let mut cached = self.root_dns.lock().await;
            *cached = Some(addr.clone());
        }

        Ok(addr)
    }

    /// Call the `dnsresolve` get method on a DNS contract.
    ///
    /// # Arguments
    ///
    /// * `contract` - The DNS resolver contract address.
    /// * `domain_bytes` - The domain in internal format (remaining bytes to resolve).
    /// * `category` - The DNS category to query.
    ///
    /// # Returns
    ///
    /// A tuple of (resolved_bits, optional record cell).
    pub async fn call_dnsresolve_async(
        &self,
        contract: &MsgAddressInt,
        domain_bytes: &[u8],
        category: &DnsCategory,
    ) -> DnsResult<(i64, Option<Arc<Cell>>)> {
        // Convert MsgAddressInt to AccountAddress
        let account = AccountAddress::new(contract.workchain, contract.address);

        // Build the stack parameters for dnsresolve:
        // - domain as a cell slice containing the domain bytes
        // - category as a 256-bit integer
        let params = build_dnsresolve_params(domain_bytes, category)?;

        // Call the get method
        let result = self
            .client
            .run_get_method_by_name(&account, "dnsresolve", &params)
            .await
            .map_err(|e| DnsError::ResolutionFailed(format!("Failed to call dnsresolve: {}", e)))?;

        // Check exit code
        if !result.is_success() {
            return Err(DnsError::ResolutionFailed(format!(
                "dnsresolve failed with exit code: {}",
                result.exit_code
            )));
        }

        // Parse the result stack
        parse_dnsresolve_result(&result)
    }

    /// Resolve a domain asynchronously using the lite client.
    ///
    /// This method performs the full iterative DNS resolution process.
    pub async fn resolve_async(
        &self,
        domain: &str,
        category: Option<DnsCategory>,
    ) -> DnsResult<Option<DnsRecord>> {
        let root = self.get_root_dns_async().await?;
        let internal = domain_to_internal(domain);
        let category = category.unwrap_or(DNS_CATEGORY_ALL);

        let mut resolver = root;
        let mut remaining = internal.as_slice();
        let mut depth = 0;
        const MAX_DEPTH: usize = 128;

        loop {
            if depth >= MAX_DEPTH {
                return Err(DnsError::MaxDepthExceeded(depth));
            }
            depth += 1;

            let (resolved_bits, record_cell) = self
                .call_dnsresolve_async(&resolver, remaining, &category)
                .await?;

            let resolved_bytes = (resolved_bits / 8) as usize;

            // No progress made
            if resolved_bytes == 0 {
                return Ok(None);
            }

            // Fully resolved
            if resolved_bytes >= remaining.len() {
                if let Some(cell) = record_cell {
                    let record = parse_dns_record_from_cell(&cell)?;
                    return Ok(Some(record));
                }
                return Ok(None);
            }

            // Partial resolution - get next resolver
            let next = match &record_cell {
                Some(cell) => {
                    let record = parse_dns_record_from_cell(cell)?;
                    match record {
                        DnsRecord::NextResolver { resolver } => resolver,
                        _ => return Err(DnsError::NoNextResolver),
                    }
                }
                None => return Err(DnsError::NoNextResolver),
            };

            resolver = next;
            remaining = &remaining[resolved_bytes..];
        }
    }

    /// Clear the cached root DNS address.
    ///
    /// Call this if you need to refresh the root DNS address.
    pub async fn clear_cache(&self) {
        let mut cached = self.root_dns.lock().await;
        *cached = None;
    }
}

impl DnsBackend for LiteClientBackend {
    fn get_root_dns(&self) -> DnsResult<MsgAddressInt> {
        // Create a new runtime for the blocking call
        // In practice, users should use the async methods directly
        let rt = tokio::runtime::Handle::try_current()
            .map_err(|_| DnsError::ResolutionFailed("No tokio runtime available".to_string()))?;

        rt.block_on(self.get_root_dns_async())
    }

    fn call_dnsresolve(
        &self,
        contract: &MsgAddressInt,
        domain_bytes: &[u8],
        category: &DnsCategory,
    ) -> DnsResult<DnsResolveResult> {
        let rt = tokio::runtime::Handle::try_current()
            .map_err(|_| DnsError::ResolutionFailed("No tokio runtime available".to_string()))?;

        let (resolved_bits, record_cell) =
            rt.block_on(self.call_dnsresolve_async(contract, domain_bytes, category))?;

        let record = if let Some(cell) = record_cell {
            Some(parse_dns_record_from_cell(&cell)?)
        } else {
            None
        };

        Ok(DnsResolveResult {
            resolved_bits: resolved_bits as usize,
            record,
        })
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Parse config parameter #4 to extract the DNS root contract address.
fn parse_config_param_4(config: &ConfigInfo) -> DnsResult<MsgAddressInt> {
    if config.config_proof.is_empty() {
        return Err(DnsError::ResolutionFailed(
            "Empty config proof".to_string(),
        ));
    }

    // Deserialize the config proof BoC
    let boc = BagOfCells::deserialize(&config.config_proof)
        .map_err(|e| DnsError::CellError(format!("Failed to parse config proof: {}", e)))?;

    let root = boc
        .single_root()
        .map_err(|e| DnsError::CellError(format!("Config proof has no single root: {}", e)))?;

    // Navigate the Merkle proof structure to find config param #4
    // The structure is: MerkleProof -> ... -> ConfigParam(4) -> dns_root_addr:MsgAddressInt
    //
    // Config param #4 contains dns_config#_ = (HashmapE 256 ^DNSResolver)
    // But we need the root resolver address which is stored as the main entry
    //
    // For simplicity, we'll look for an address in the config structure
    let addr = extract_address_from_config(root)?;

    Ok(addr)
}

/// Extract the DNS root address from the config cell.
///
/// Config param #4 structure:
/// ```tlb
/// dns_config#_ = (HashmapE 256 ^DNSResolver)
/// ```
/// The root DNS address is typically stored as the default/first entry.
fn extract_address_from_config(cell: &Cell) -> DnsResult<MsgAddressInt> {
    // Try to parse as a Merkle proof and navigate to find the address
    // This is a simplified implementation - real implementation would
    // need to properly navigate the config structure

    let mut slice = CellSlice::new(cell);

    // Skip Merkle proof prefix if present (0x03 for merkle_proof)
    if slice.bits_left() >= 8 {
        let prefix = slice.load_u8().map_err(|e| DnsError::CellError(e.to_string()))?;
        if prefix == 0x03 {
            // This is a Merkle proof, need to navigate to virtual root
            // Skip the hash (256 bits) and depth (16 bits)
            if slice.refs_left() > 0 {
                let inner = slice.load_ref().map_err(|e| DnsError::CellError(e.to_string()))?;
                return extract_address_from_config_inner(inner);
            }
        }
    }

    // Reset and try direct parsing
    let slice = CellSlice::new(cell);
    extract_address_from_config_inner_slice(slice)
}

fn extract_address_from_config_inner(cell: &Cell) -> DnsResult<MsgAddressInt> {
    let slice = CellSlice::new(cell);
    extract_address_from_config_inner_slice(slice)
}

fn extract_address_from_config_inner_slice(mut slice: CellSlice) -> DnsResult<MsgAddressInt> {
    // Try to find an address in the cell structure
    // Config param #4 contains the DNS root contract address

    // First, check if there are references to navigate
    if slice.refs_left() > 0 {
        // Navigate to find the address
        let inner = slice.load_ref().map_err(|e| DnsError::CellError(e.to_string()))?;
        let inner_slice = CellSlice::new(inner);

        if inner_slice.bits_left() >= 267 {
            // Might contain an address (2 bits type + 1 bit anycast + 8 bits workchain + 256 bits address)
            let mut s = inner_slice;
            if let Ok(addr) = s.load_address() {
                if let MsgAddress::Internal { workchain, address } = addr {
                    return Ok(MsgAddressInt { workchain, address });
                }
            }
        }

        // Recursively search
        return extract_address_from_config_inner(inner);
    }

    // Try to load address directly if enough bits
    if slice.bits_left() >= 267 {
        if let Ok(addr) = slice.load_address() {
            if let MsgAddress::Internal { workchain, address } = addr {
                return Ok(MsgAddressInt { workchain, address });
            }
        }
    }

    Err(DnsError::ResolutionFailed(
        "Could not find DNS root address in config param #4".to_string(),
    ))
}

/// VmStackValue tag constants for TVM stack serialization.
const VM_STK_INT: u16 = 0x0201;     // vm_stk_int#0201 value:int257
const VM_STK_SLICE: u8 = 0x04;      // vm_stk_slice#04 _:VmCellSlice

/// Build the parameters for the dnsresolve get method.
///
/// The dnsresolve method takes (in stack order, bottom to top):
/// - domain: Slice containing the domain bytes
/// - category: 256-bit integer (category hash)
///
/// The liteserver expects parameters in proper TVM stack format:
/// ```tlb
/// vm_stack#_ depth:(## 24) stack:(VmStackList depth) = VmStack;
/// vm_stk_int#0201 value:int257 = VmStackValue;
/// vm_stk_slice#04 _:VmCellSlice = VmStackValue;
/// ```
fn build_dnsresolve_params(domain_bytes: &[u8], category: &DnsCategory) -> DnsResult<Vec<u8>> {
    // Build the domain cell
    let mut domain_builder = CellBuilder::new();
    domain_builder
        .store_bytes(domain_bytes)
        .map_err(|e| DnsError::CellError(e.to_string()))?;
    let domain_cell = domain_builder
        .build()
        .map_err(|e| DnsError::CellError(e.to_string()))?;

    // Build the TVM stack in proper format
    // Stack depth = 2 (domain slice + category int)
    let mut builder = CellBuilder::new();

    // Store stack depth (24 bits)
    builder
        .store_uint(2, 24)
        .map_err(|e| DnsError::CellError(e.to_string()))?;

    // Stack entry 1: domain as vm_stk_slice#04
    // VmCellSlice format: st_bits:(## 10) end_bits:(## 10) st_ref:(#<= 4) end_ref:(#<= 4) cell:^Cell
    builder
        .store_u8(VM_STK_SLICE)
        .map_err(|e| DnsError::CellError(e.to_string()))?;
    // st_bits = 0 (start at bit 0)
    builder
        .store_uint(0, 10)
        .map_err(|e| DnsError::CellError(e.to_string()))?;
    // end_bits = domain_bytes.len() * 8 (bits used)
    builder
        .store_uint((domain_bytes.len() * 8) as u64, 10)
        .map_err(|e| DnsError::CellError(e.to_string()))?;
    // st_ref = 0 (start at ref 0)
    builder
        .store_uint(0, 3)
        .map_err(|e| DnsError::CellError(e.to_string()))?;
    // end_ref = 0 (no refs in domain slice)
    builder
        .store_uint(0, 3)
        .map_err(|e| DnsError::CellError(e.to_string()))?;
    // cell reference
    builder
        .store_ref(Arc::new(domain_cell))
        .map_err(|e| DnsError::CellError(e.to_string()))?;

    // Stack entry 2: category as vm_stk_int#0201
    builder
        .store_u16(VM_STK_INT)
        .map_err(|e| DnsError::CellError(e.to_string()))?;
    // int257 = sign bit (1) + 256-bit value
    // For category hash, it's always positive, so sign bit = 0
    builder
        .store_bit(false)
        .map_err(|e| DnsError::CellError(e.to_string()))?;
    builder
        .store_bytes(category)
        .map_err(|e| DnsError::CellError(e.to_string()))?;

    let params_cell = builder
        .build()
        .map_err(|e| DnsError::CellError(e.to_string()))?;

    let boc = BagOfCells::from_root(params_cell);
    boc.serialize()
        .map_err(|e| DnsError::CellError(e.to_string()))
}

/// Parse the result of a dnsresolve call.
///
/// Returns (resolved_bits, record_cell).
fn parse_dnsresolve_result(result: &RunMethodResult) -> DnsResult<(i64, Option<Arc<Cell>>)> {
    // Parse the result stack from the BoC
    let result_bytes = result.result.as_ref().ok_or_else(|| {
        DnsError::ResolutionFailed("No result in dnsresolve response".to_string())
    })?;

    if result_bytes.is_empty() {
        return Err(DnsError::ResolutionFailed(
            "Empty result in dnsresolve response".to_string(),
        ));
    }

    // Deserialize the result BoC
    let boc = BagOfCells::deserialize(result_bytes)
        .map_err(|e| DnsError::CellError(format!("Failed to parse result: {}", e)))?;

    let root = boc
        .single_root()
        .map_err(|e| DnsError::CellError(format!("Result has no single root: {}", e)))?;

    // The result is a stack with two elements:
    // [0]: resolved_bits (integer)
    // [1]: record cell or null
    //
    // Parse the TVM stack structure
    let mut slice = CellSlice::new(root);

    // Read stack depth (24-bit VarUInt)
    let depth = slice.load_uint(24).map_err(|e| DnsError::CellError(e.to_string()))? as usize;

    if depth < 2 {
        return Err(DnsError::ResolutionFailed(format!(
            "Expected at least 2 stack entries, got {}",
            depth
        )));
    }

    // Parse first stack entry (resolved_bits)
    let resolved_bits = parse_stack_int(&mut slice)?;

    // Parse second stack entry (record cell)
    let record_cell = parse_stack_cell(&mut slice)?;

    Ok((resolved_bits, record_cell))
}

/// Parse an integer from the TVM stack.
fn parse_stack_int(slice: &mut CellSlice) -> DnsResult<i64> {
    // VmStackValue format:
    // vm_stk_null#00 = VmStackValue
    // vm_stk_tinyint#01 value:int64 = VmStackValue
    // vm_stk_int#0201 value:int257 = VmStackValue
    // ... other types

    let tag = slice.load_u8().map_err(|e| DnsError::CellError(e.to_string()))?;

    match tag {
        0x00 => Ok(0), // null treated as 0
        0x01 => {
            // tinyint (64-bit)
            slice.load_i64().map_err(|e| DnsError::CellError(e.to_string()))
        }
        0x02 => {
            // Check for int257
            let sub_tag = slice.load_u8().map_err(|e| DnsError::CellError(e.to_string()))?;
            if sub_tag == 0x01 {
                // int257, load as big integer (simplified: load as i64 if possible)
                // For DNS, resolved_bits should fit in i64
                let bytes = slice.load_bytes(32).map_err(|e| DnsError::CellError(e.to_string()))?;
                // Interpret as big-endian i64 (simplified)
                let mut value: i64 = 0;
                for b in bytes.iter().take(8) {
                    value = (value << 8) | (*b as i64);
                }
                Ok(value)
            } else {
                Err(DnsError::ResolutionFailed(format!(
                    "Unknown int stack value sub-tag: {:02x}",
                    sub_tag
                )))
            }
        }
        _ => Err(DnsError::ResolutionFailed(format!(
            "Expected integer stack value, got tag: {:02x}",
            tag
        ))),
    }
}

/// Parse a cell from the TVM stack.
fn parse_stack_cell(slice: &mut CellSlice) -> DnsResult<Option<Arc<Cell>>> {
    // VmStackValue format:
    // vm_stk_null#00 = VmStackValue
    // vm_stk_cell#03 cell:^Cell = VmStackValue
    // vm_stk_slice#04 ... = VmStackValue

    let tag = slice.load_u8().map_err(|e| DnsError::CellError(e.to_string()))?;

    match tag {
        0x00 => Ok(None), // null
        0x03 => {
            // cell reference
            let cell = slice.load_ref().map_err(|e| DnsError::CellError(e.to_string()))?;
            Ok(Some(Arc::new(cell.clone())))
        }
        0x04 => {
            // slice - load the cell it references
            if slice.refs_left() > 0 {
                let cell = slice.load_ref().map_err(|e| DnsError::CellError(e.to_string()))?;
                Ok(Some(Arc::new(cell.clone())))
            } else {
                Ok(None)
            }
        }
        _ => Err(DnsError::ResolutionFailed(format!(
            "Expected cell stack value, got tag: {:02x}",
            tag
        ))),
    }
}

/// Parse a DNS record from a cell.
///
/// DNS records are encoded with TL-B prefixes:
/// - 0x9fd3: dns_smc_address
/// - 0xba93: dns_next_resolver
/// - 0xad01: dns_adnl_address
/// - 0x7473: dns_storage_address
pub fn parse_dns_record_from_cell(cell: &Cell) -> DnsResult<DnsRecord> {
    let mut slice = CellSlice::new(cell);

    // Load the 16-bit prefix
    let prefix = slice.load_u16().map_err(|e| DnsError::CellError(e.to_string()))?;

    match prefix {
        0x9fd3 => {
            // dns_smc_address#9fd3 smc_addr:MsgAddressInt flags:(## 8) = DNSRecord
            let addr = slice.load_address().map_err(|e| DnsError::CellError(e.to_string()))?;
            let flags = slice.load_u8().map_err(|e| DnsError::CellError(e.to_string()))?;

            match addr {
                MsgAddress::Internal { workchain, address } => {
                    Ok(DnsRecord::SmcAddress {
                        address: MsgAddressInt { workchain, address },
                        flags,
                    })
                }
                _ => Err(DnsError::InvalidRecord(
                    "dns_smc_address contains non-internal address".to_string(),
                )),
            }
        }
        0xba93 => {
            // dns_next_resolver#ba93 resolver:MsgAddressInt = DNSRecord
            let addr = slice.load_address().map_err(|e| DnsError::CellError(e.to_string()))?;

            match addr {
                MsgAddress::Internal { workchain, address } => {
                    Ok(DnsRecord::NextResolver {
                        resolver: MsgAddressInt { workchain, address },
                    })
                }
                _ => Err(DnsError::InvalidRecord(
                    "dns_next_resolver contains non-internal address".to_string(),
                )),
            }
        }
        0xad01 => {
            // dns_adnl_address#ad01 adnl_addr:bits256 flags:(## 8) { flags <= 1 }
            //                       proto_list:flags.0?ProtoList = DNSRecord
            let adnl_bytes = slice.load_bytes(32).map_err(|e| DnsError::CellError(e.to_string()))?;
            let mut address = [0u8; 32];
            address.copy_from_slice(&adnl_bytes);

            let flags = slice.load_u8().map_err(|e| DnsError::CellError(e.to_string()))?;

            let mut protocols = Vec::new();
            if flags & 1 != 0 {
                // Load ProtoList
                // proto_list#0 list:(## 8) = ProtoList
                // Each protocol is encoded as a TL-B constructor
                if slice.bits_left() >= 8 {
                    let proto_count = slice.load_u8().unwrap_or(0);
                    for _ in 0..proto_count {
                        if slice.bits_left() >= 8 {
                            match slice.load_u8() {
                                Ok(0) => protocols.push(Protocol::Http),
                                Ok(1) => protocols.push(Protocol::Https),
                                _ => {} // Unknown protocol, skip
                            }
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
        0x7473 => {
            // dns_storage_address#7473 bag_id:bits256 = DNSRecord
            let bag_bytes = slice.load_bytes(32).map_err(|e| DnsError::CellError(e.to_string()))?;
            let mut bag_id = [0u8; 32];
            bag_id.copy_from_slice(&bag_bytes);

            Ok(DnsRecord::StorageAddress { bag_id })
        }
        _ => {
            // Unknown record type
            Err(DnsError::UnknownRecordType { prefix })
        }
    }
}

// ============================================================================
// Async API Extension for TonDns
// ============================================================================

use crate::resolver::TonDns;

impl TonDns<LiteClientBackend> {
    /// Create a new TonDns resolver with a LiteClient backend.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use std::sync::Arc;
    /// use ton_dns::TonDns;
    /// use ton_adnl::LiteClient;
    ///
    /// async fn example() -> Result<(), Box<dyn std::error::Error>> {
    ///     let client = Arc::new(LiteClient::connect("1.2.3.4", 12345, &[0u8; 32]).await?);
    ///     let dns = TonDns::with_lite_client(client);
    ///     // Use dns.resolve_wallet(), etc.
    ///     Ok(())
    /// }
    /// ```
    pub fn with_lite_client(client: Arc<LiteClient>) -> Self {
        TonDns::new(LiteClientBackend::new(client))
    }

    /// Resolve a domain asynchronously.
    ///
    /// This is the preferred method when using LiteClientBackend as it
    /// properly handles async I/O.
    pub async fn resolve_async(&self, domain: &str) -> DnsResult<Option<DnsRecord>> {
        let domain = crate::domain::TonDomain::parse_normalized(domain)?;
        self.backend().resolve_async(domain.as_str(), None).await
    }

    /// Resolve a wallet address asynchronously.
    pub async fn resolve_wallet_async(&self, domain: &str) -> DnsResult<MsgAddressInt> {
        use crate::categories::DNS_CATEGORY_WALLET;

        let domain = crate::domain::TonDomain::parse_normalized(domain)?;
        let record = self
            .backend()
            .resolve_async(domain.as_str(), Some(DNS_CATEGORY_WALLET))
            .await?;

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

    /// Resolve a TON Site ADNL address asynchronously.
    pub async fn resolve_site_async(&self, domain: &str) -> DnsResult<[u8; 32]> {
        use crate::categories::DNS_CATEGORY_SITE;

        let domain = crate::domain::TonDomain::parse_normalized(domain)?;
        let record = self
            .backend()
            .resolve_async(domain.as_str(), Some(DNS_CATEGORY_SITE))
            .await?;

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

    /// Resolve a TON Storage bag ID asynchronously.
    pub async fn resolve_storage_async(&self, domain: &str) -> DnsResult<[u8; 32]> {
        use crate::categories::DNS_CATEGORY_STORAGE;

        let domain = crate::domain::TonDomain::parse_normalized(domain)?;
        let record = self
            .backend()
            .resolve_async(domain.as_str(), Some(DNS_CATEGORY_STORAGE))
            .await?;

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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_dns_record_smc_address() {
        // Build a test cell with dns_smc_address record
        let mut builder = CellBuilder::new();
        // Prefix
        builder.store_u16(0x9fd3).unwrap();
        // Address: addr_std$10 anycast:(Maybe Anycast) workchain_id:int8 address:bits256
        builder.store_uint(0b10, 2).unwrap(); // addr_std
        builder.store_bit(false).unwrap(); // no anycast
        builder.store_i8(0).unwrap(); // workchain 0
        builder.store_bytes(&[0xAB; 32]).unwrap(); // address
        builder.store_u8(0).unwrap(); // flags
        let cell = builder.build().unwrap();

        let record = parse_dns_record_from_cell(&cell).unwrap();
        match record {
            DnsRecord::SmcAddress { address, flags } => {
                assert_eq!(address.workchain, 0);
                assert_eq!(address.address, [0xAB; 32]);
                assert_eq!(flags, 0);
            }
            _ => panic!("Expected SmcAddress"),
        }
    }

    #[test]
    fn test_parse_dns_record_next_resolver() {
        let mut builder = CellBuilder::new();
        builder.store_u16(0xba93).unwrap();
        builder.store_uint(0b10, 2).unwrap(); // addr_std
        builder.store_bit(false).unwrap(); // no anycast
        builder.store_i8(-1).unwrap(); // workchain -1 (masterchain)
        builder.store_bytes(&[0xCD; 32]).unwrap(); // address
        let cell = builder.build().unwrap();

        let record = parse_dns_record_from_cell(&cell).unwrap();
        match record {
            DnsRecord::NextResolver { resolver } => {
                assert_eq!(resolver.workchain, -1);
                assert_eq!(resolver.address, [0xCD; 32]);
            }
            _ => panic!("Expected NextResolver"),
        }
    }

    #[test]
    fn test_parse_dns_record_adnl_address() {
        let mut builder = CellBuilder::new();
        builder.store_u16(0xad01).unwrap();
        builder.store_bytes(&[0xEF; 32]).unwrap(); // ADNL address
        builder.store_u8(0).unwrap(); // flags (no protocols)
        let cell = builder.build().unwrap();

        let record = parse_dns_record_from_cell(&cell).unwrap();
        match record {
            DnsRecord::AdnlAddress { address, flags, protocols } => {
                assert_eq!(address, [0xEF; 32]);
                assert_eq!(flags, 0);
                assert!(protocols.is_empty());
            }
            _ => panic!("Expected AdnlAddress"),
        }
    }

    #[test]
    fn test_parse_dns_record_storage_address() {
        let mut builder = CellBuilder::new();
        builder.store_u16(0x7473).unwrap();
        builder.store_bytes(&[0x12; 32]).unwrap(); // bag ID
        let cell = builder.build().unwrap();

        let record = parse_dns_record_from_cell(&cell).unwrap();
        match record {
            DnsRecord::StorageAddress { bag_id } => {
                assert_eq!(bag_id, [0x12; 32]);
            }
            _ => panic!("Expected StorageAddress"),
        }
    }

    #[test]
    fn test_parse_dns_record_unknown() {
        let mut builder = CellBuilder::new();
        builder.store_u16(0xFFFF).unwrap(); // Unknown prefix
        builder.store_bytes(&[0x00; 10]).unwrap();
        let cell = builder.build().unwrap();

        let result = parse_dns_record_from_cell(&cell);
        assert!(matches!(result, Err(DnsError::UnknownRecordType { prefix: 0xFFFF })));
    }

    #[test]
    fn test_build_dnsresolve_params() {
        let domain_bytes = b"ton\0test\0";
        let category = [0u8; 32]; // All categories

        let params = build_dnsresolve_params(domain_bytes, &category).unwrap();
        assert!(!params.is_empty());

        // Should be valid BoC
        let boc = BagOfCells::deserialize(&params).unwrap();
        let root = boc.single_root().unwrap();

        // Verify TVM stack format
        let mut slice = CellSlice::new(root);

        // Check stack depth (24 bits) = 2
        let depth = slice.load_uint(24).unwrap();
        assert_eq!(depth, 2);

        // Check first entry: vm_stk_slice#04
        let tag = slice.load_u8().unwrap();
        assert_eq!(tag, 0x04);

        // VmCellSlice: st_bits (10) + end_bits (10) + st_ref (3) + end_ref (3)
        let st_bits = slice.load_uint(10).unwrap();
        let end_bits = slice.load_uint(10).unwrap();
        let st_ref = slice.load_uint(3).unwrap();
        let end_ref = slice.load_uint(3).unwrap();

        assert_eq!(st_bits, 0);
        assert_eq!(end_bits as usize, domain_bytes.len() * 8);
        assert_eq!(st_ref, 0);
        assert_eq!(end_ref, 0);

        // Skip cell reference
        let _domain_cell = slice.load_ref().unwrap();

        // Check second entry: vm_stk_int#0201
        let int_tag = slice.load_u16().unwrap();
        assert_eq!(int_tag, 0x0201);

        // Sign bit (should be 0 for positive)
        let sign = slice.load_bit().unwrap();
        assert!(!sign);

        // 256-bit category value
        let cat_bytes = slice.load_bytes(32).unwrap();
        assert_eq!(cat_bytes, category.to_vec());
    }
}
