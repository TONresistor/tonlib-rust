//! DHT Value types for Storage Node announcements
//!
//! This module implements the storage provider announcement structures that are
//! published to the DHT for peer discovery in TON Storage.
//!
//! # Overview
//!
//! Storage nodes announce their availability via DHT values containing:
//! - Provider identification (Ed25519 public key)
//! - Network address (IP + port)
//! - Storage capabilities (available/used space, supported chunk sizes)
//! - Metadata (region, bandwidth, latency, uptime)
//! - Cryptographic signatures for authenticity
//!
//! # Example
//!
//! ```rust,no_run
//! use ton_storage::dht_value::{StorageNodeValue, StorageMetadata};
//! use ton_crypto::Ed25519Keypair;
//! use std::net::SocketAddr;
//!
//! async fn example() -> Result<(), Box<dyn std::error::Error>> {
//!     // Create a provider keypair
//!     let keypair = Ed25519Keypair::generate();
//!
//!     // Define provider address
//!     let addr: SocketAddr = "192.168.1.100:30303".parse()?;
//!
//!     // Create the storage node value
//!     let storage_value = StorageNodeValue::new(&keypair, addr)
//!         .with_available_space(1024 * 1024 * 100) // 100 GB
//!         .with_used_space(1024 * 1024 * 50) // 50 GB
//!         .with_bags_count(1000)
//!         .with_max_chunk_size(1024 * 1024) // 1 MB
//!         .with_ttl(86400); // 24 hours
//!
//!     // Add metadata
//!     let metadata = StorageMetadata {
//!         region: Some("us-east".to_string()),
//!         bandwidth_kbps: 10000,
//!         download_latency_ms: 50,
//!         uptime_percent: 99,
//!         custom_data: vec![],
//!     };
//!     let storage_value = storage_value.with_metadata(metadata);
//!
//!     // Sign the value
//!     let signature = storage_value.sign(&keypair).await?;
//!
//!     // Verify signature
//!     storage_value.verify_signature(&signature)?;
//!
//!     Ok(())
//! }
//! ```

use std::net::SocketAddr;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::error::{DhtSigningError, StorageError, StorageResult};
use ton_crypto::{sha256, Ed25519Keypair};

// Constants
const MIN_TTL: u32 = 60; // 1 minute
const MAX_TTL: u32 = 2_592_000; // 30 days
const DEFAULT_TTL: u32 = 86_400; // 24 hours
const MAX_CUSTOM_DATA: usize = 256;
const VERSION: u32 = 1;
const DHT_KEY_PREFIX: &[u8] = b"storage";

/// Storage metadata containing additional provider information.
///
/// This structure holds non-critical metadata about a storage provider that helps
/// clients make informed decisions about which providers to use.
#[derive(Debug, Clone)]
pub struct StorageMetadata {
    /// Geographic region where the provider is located (e.g., "us-east", "eu-west").
    pub region: Option<String>,

    /// Advertised upstream bandwidth capacity in kilobits per second.
    pub bandwidth_kbps: u32,

    /// Estimated download latency from provider in milliseconds.
    pub download_latency_ms: u32,

    /// Provider uptime percentage (0-100).
    pub uptime_percent: u8,

    /// Custom data for future extensions (max 256 bytes).
    pub custom_data: Vec<u8>,
}

impl StorageMetadata {
    /// Create new storage metadata with default values.
    pub fn new() -> Self {
        Self {
            region: None,
            bandwidth_kbps: 0,
            download_latency_ms: 0,
            uptime_percent: 100,
            custom_data: Vec::new(),
        }
    }

    /// Validate the metadata.
    fn validate(&self) -> StorageResult<()> {
        if self.custom_data.len() > MAX_CUSTOM_DATA {
            return Err(StorageError::SerializationError(format!(
                "custom_data exceeds max size: {} > {}",
                self.custom_data.len(),
                MAX_CUSTOM_DATA
            )));
        }

        if self.uptime_percent > 100 {
            return Err(StorageError::SerializationError(
                "uptime_percent must be 0-100".to_string(),
            ));
        }

        Ok(())
    }
}

impl Default for StorageMetadata {
    fn default() -> Self {
        Self::new()
    }
}

/// Signature for a storage node value.
///
/// This structure contains the cryptographic proof of the storage node value's authenticity.
#[derive(Debug, Clone)]
pub struct StorageNodeValueSignature {
    /// Ed25519 signature (64 bytes).
    pub signature: [u8; 64],

    /// Ed25519 public key used for signing (32 bytes).
    pub public_key: [u8; 32],

    /// Unix timestamp when the signature was created.
    pub signature_timestamp: u64,
}

impl StorageNodeValueSignature {
    /// Verify this signature against the given value data.
    pub fn verify(&self, value_data: &[u8]) -> StorageResult<()> {
        ton_crypto::verify_signature(&self.public_key, value_data, &self.signature)
            .map_err(|e| {
                StorageError::DhtSigningError(DhtSigningError::SigningFailed(format!(
                    "Signature verification failed: {}",
                    e
                )))
            })
    }
}

/// A storage node value announcing provider availability in the DHT.
///
/// This is the main structure published to the DHT for peer discovery. It contains
/// all information about a storage provider's capabilities and capacity.
#[derive(Debug, Clone)]
pub struct StorageNodeValue {
    /// Ed25519 public key identifying the provider (32 bytes).
    pub provider_id: [u8; 32],

    /// Network address (IP + port) for ADNL connections.
    pub address: SocketAddr,

    /// Protocol version (currently 1).
    pub version: u32,

    /// Bit flags for capabilities (1=uploads, 2=downloads, 4=public).
    pub flags: u8,

    /// Available storage space in bytes.
    pub available_space: u64,

    /// Currently used storage space in bytes.
    pub used_space: u64,

    /// Number of bags currently hosted by this provider.
    pub bags_count: u32,

    /// Maximum chunk size supported by this provider in bytes.
    pub max_chunk_size: u32,

    /// Optional metadata with additional provider information.
    pub metadata: Option<StorageMetadata>,

    /// Time to live in seconds (default 86400 = 24 hours).
    pub ttl: u32,

    /// Unix timestamp when this value was created.
    pub created_at: u64,

    /// Unix timestamp when this value expires.
    pub expires_at: u64,
}

impl StorageNodeValue {
    /// Create a new storage node value.
    pub fn new(keypair: &Ed25519Keypair, address: SocketAddr) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let ttl = DEFAULT_TTL;
        let expires_at = now + ttl as u64;

        Self {
            provider_id: keypair.public_key,
            address,
            version: VERSION,
            flags: 0,
            available_space: 0,
            used_space: 0,
            bags_count: 0,
            max_chunk_size: 0,
            metadata: None,
            ttl,
            created_at: now,
            expires_at,
        }
    }

    /// Set available space (builder pattern).
    pub fn with_available_space(mut self, space: u64) -> Self {
        self.available_space = space;
        self
    }

    /// Set used space (builder pattern).
    pub fn with_used_space(mut self, space: u64) -> Self {
        self.used_space = space;
        self
    }

    /// Set bags count (builder pattern).
    pub fn with_bags_count(mut self, count: u32) -> Self {
        self.bags_count = count;
        self
    }

    /// Set max chunk size (builder pattern).
    pub fn with_max_chunk_size(mut self, size: u32) -> Self {
        self.max_chunk_size = size;
        self
    }

    /// Set metadata (builder pattern).
    pub fn with_metadata(mut self, metadata: StorageMetadata) -> Self {
        self.metadata = Some(metadata);
        self
    }

    /// Set TTL in seconds (builder pattern).
    pub fn with_ttl(mut self, ttl: u32) -> Self {
        self.ttl = ttl;
        self.expires_at = self.created_at + ttl as u64;
        self
    }

    /// Set flags (builder pattern).
    pub fn with_flags(mut self, flags: u8) -> Self {
        self.flags = flags;
        self
    }

    /// Check if provider accepts uploads.
    pub fn accepts_uploads(&self) -> bool {
        (self.flags & 1) != 0
    }

    /// Check if provider accepts downloads.
    pub fn accepts_downloads(&self) -> bool {
        (self.flags & 2) != 0
    }

    /// Check if provider is public (advertised to all).
    pub fn is_public(&self) -> bool {
        (self.flags & 4) != 0
    }

    /// Set whether provider accepts uploads.
    pub fn set_accepts_uploads(&mut self, accept: bool) {
        if accept {
            self.flags |= 1;
        } else {
            self.flags &= !1;
        }
    }

    /// Set whether provider accepts downloads.
    pub fn set_accepts_downloads(&mut self, accept: bool) {
        if accept {
            self.flags |= 2;
        } else {
            self.flags &= !2;
        }
    }

    /// Set whether provider is public.
    pub fn set_public(&mut self, public: bool) {
        if public {
            self.flags |= 4;
        } else {
            self.flags &= !4;
        }
    }

    /// Validate the storage node value.
    fn validate(&self) -> StorageResult<()> {
        // Version must be 1
        if self.version != VERSION {
            return Err(StorageError::SerializationError(format!(
                "Unsupported version: {}",
                self.version
            )));
        }

        // Available space must be >= used space
        if self.available_space < self.used_space {
            return Err(StorageError::SerializationError(
                "available_space must be >= used_space".to_string(),
            ));
        }

        // Validate address
        if self.address.port() == 0 {
            return Err(StorageError::SerializationError(
                "Invalid port: must be > 0".to_string(),
            ));
        }

        // Validate TTL
        if self.ttl < MIN_TTL || self.ttl > MAX_TTL {
            return Err(StorageError::SerializationError(format!(
                "TTL out of range: {} (valid: {}-{})",
                self.ttl, MIN_TTL, MAX_TTL
            )));
        }

        // Validate metadata if present
        if let Some(metadata) = &self.metadata {
            metadata.validate()?;
        }

        Ok(())
    }

    /// Serialize the value to bytes for signing.
    pub fn to_bytes(&self) -> StorageResult<Vec<u8>> {
        self.validate()?;

        let mut bytes = Vec::new();

        // Provider ID (32 bytes)
        bytes.extend_from_slice(&self.provider_id);

        // Address (variable length)
        let addr_bytes = match self.address.ip() {
            std::net::IpAddr::V4(ipv4) => {
                let mut addr_data = vec![4u8]; // IPv4 marker
                addr_data.extend_from_slice(&ipv4.octets());
                addr_data
            }
            std::net::IpAddr::V6(ipv6) => {
                let mut addr_data = vec![6u8]; // IPv6 marker
                addr_data.extend_from_slice(&ipv6.octets());
                addr_data
            }
        };
        bytes.push(addr_bytes.len() as u8);
        bytes.extend_from_slice(&addr_bytes);

        // Port (2 bytes, big-endian)
        bytes.extend_from_slice(&self.address.port().to_be_bytes());

        // Version (4 bytes)
        bytes.extend_from_slice(&self.version.to_be_bytes());

        // Flags (1 byte)
        bytes.push(self.flags);

        // Available space (8 bytes)
        bytes.extend_from_slice(&self.available_space.to_be_bytes());

        // Used space (8 bytes)
        bytes.extend_from_slice(&self.used_space.to_be_bytes());

        // Bags count (4 bytes)
        bytes.extend_from_slice(&self.bags_count.to_be_bytes());

        // Max chunk size (4 bytes)
        bytes.extend_from_slice(&self.max_chunk_size.to_be_bytes());

        // Metadata (variable length)
        if let Some(metadata) = &self.metadata {
            bytes.push(1u8); // metadata present marker

            // Region
            if let Some(region) = &metadata.region {
                bytes.push(1u8); // region present marker
                let region_bytes = region.as_bytes();
                bytes.push(region_bytes.len().min(255) as u8);
                bytes.extend_from_slice(&region_bytes[..region_bytes.len().min(255)]);
            } else {
                bytes.push(0u8); // no region
            }

            // Bandwidth
            bytes.extend_from_slice(&metadata.bandwidth_kbps.to_be_bytes());

            // Download latency
            bytes.extend_from_slice(&metadata.download_latency_ms.to_be_bytes());

            // Uptime percent
            bytes.push(metadata.uptime_percent);

            // Custom data
            bytes.push(metadata.custom_data.len().min(255) as u8);
            bytes.extend_from_slice(&metadata.custom_data[..metadata.custom_data.len().min(255)]);
        } else {
            bytes.push(0u8); // no metadata
        }

        // TTL (4 bytes)
        bytes.extend_from_slice(&self.ttl.to_be_bytes());

        // Created at (8 bytes)
        bytes.extend_from_slice(&self.created_at.to_be_bytes());

        // Expires at (8 bytes)
        bytes.extend_from_slice(&self.expires_at.to_be_bytes());

        Ok(bytes)
    }

    /// Sign this value with the given keypair.
    pub async fn sign(&self, keypair: &Ed25519Keypair) -> StorageResult<StorageNodeValueSignature> {
        let data_to_sign = self.to_bytes()?;
        let signature_bytes = keypair.sign(&data_to_sign);

        let mut signature = [0u8; 64];
        signature.copy_from_slice(&signature_bytes);

        let signature_timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        Ok(StorageNodeValueSignature {
            signature,
            public_key: keypair.public_key,
            signature_timestamp,
        })
    }

    /// Verify a signature against this value.
    pub fn verify_signature(&self, sig: &StorageNodeValueSignature) -> StorageResult<()> {
        // Verify public key matches
        if sig.public_key != self.provider_id {
            return Err(StorageError::DhtSigningError(DhtSigningError::SigningFailed(
                "Signature public key does not match provider ID".to_string(),
            )));
        }

        let data_to_verify = self.to_bytes()?;
        sig.verify(&data_to_verify)
    }

    /// Check if this value has expired.
    pub fn is_expired(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        now >= self.expires_at
    }

    /// Get time remaining before expiration in seconds.
    /// Returns negative number if already expired.
    pub fn time_to_expiry(&self) -> i64 {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        self.expires_at as i64 - now
    }

    /// Calculate the DHT key for this provider.
    /// Uses SHA256("storage" || provider_id)
    pub fn calculate_dht_key(provider_id: &[u8; 32]) -> [u8; 32] {
        let mut data = Vec::with_capacity(39);
        data.extend_from_slice(DHT_KEY_PREFIX);
        data.extend_from_slice(provider_id);
        sha256(&data)
    }

    /// Get the DHT key for this value.
    pub fn dht_key(&self) -> [u8; 32] {
        Self::calculate_dht_key(&self.provider_id)
    }
}

/// Builder for creating StorageNodeValue instances with a fluent API.
pub struct StorageNodeValueBuilder {
    keypair_public_key: [u8; 32],
    address: SocketAddr,
    available_space: u64,
    used_space: u64,
    bags_count: u32,
    max_chunk_size: u32,
    metadata: Option<StorageMetadata>,
    ttl: u32,
    flags: u8,
}

impl StorageNodeValueBuilder {
    /// Create a new builder.
    pub fn new(keypair: &Ed25519Keypair, address: SocketAddr) -> Self {
        Self {
            keypair_public_key: keypair.public_key,
            address,
            available_space: 0,
            used_space: 0,
            bags_count: 0,
            max_chunk_size: 0,
            metadata: None,
            ttl: DEFAULT_TTL,
            flags: 0,
        }
    }

    /// Set available space.
    pub fn available_space(mut self, space: u64) -> Self {
        self.available_space = space;
        self
    }

    /// Set used space.
    pub fn used_space(mut self, space: u64) -> Self {
        self.used_space = space;
        self
    }

    /// Set bags count.
    pub fn bags_count(mut self, count: u32) -> Self {
        self.bags_count = count;
        self
    }

    /// Set max chunk size.
    pub fn max_chunk_size(mut self, size: u32) -> Self {
        self.max_chunk_size = size;
        self
    }

    /// Set metadata.
    pub fn metadata(mut self, metadata: StorageMetadata) -> Self {
        self.metadata = Some(metadata);
        self
    }

    /// Set TTL.
    pub fn ttl(mut self, ttl: u32) -> Self {
        self.ttl = ttl;
        self
    }

    /// Set flags.
    pub fn flags(mut self, flags: u8) -> Self {
        self.flags = flags;
        self
    }

    /// Build the StorageNodeValue.
    pub fn build(self) -> StorageNodeValue {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        StorageNodeValue {
            provider_id: self.keypair_public_key,
            address: self.address,
            version: VERSION,
            flags: self.flags,
            available_space: self.available_space,
            used_space: self.used_space,
            bags_count: self.bags_count,
            max_chunk_size: self.max_chunk_size,
            metadata: self.metadata,
            ttl: self.ttl,
            created_at: now,
            expires_at: now + self.ttl as u64,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_storage_node_value() {
        let keypair = Ed25519Keypair::generate();
        let addr: SocketAddr = "192.168.1.100:30303".parse().unwrap();

        let value = StorageNodeValue::new(&keypair, addr);

        assert_eq!(value.provider_id, keypair.public_key);
        assert_eq!(value.address, addr);
        assert_eq!(value.version, VERSION);
        assert!(!value.is_expired());
    }

    #[test]
    fn test_builder_pattern() {
        let keypair = Ed25519Keypair::generate();
        let addr: SocketAddr = "10.0.0.1:8080".parse().unwrap();

        let value = StorageNodeValue::new(&keypair, addr)
            .with_available_space(1024 * 1024 * 100)
            .with_used_space(1024 * 1024 * 50)
            .with_bags_count(42)
            .with_max_chunk_size(1024 * 1024)
            .with_ttl(3600)
            .with_flags(7); // all flags set

        assert_eq!(value.available_space, 1024 * 1024 * 100);
        assert_eq!(value.used_space, 1024 * 1024 * 50);
        assert_eq!(value.bags_count, 42);
        assert_eq!(value.max_chunk_size, 1024 * 1024);
        assert_eq!(value.ttl, 3600);
        assert_eq!(value.flags, 7);
    }

    #[test]
    fn test_serialization_roundtrip() {
        let keypair = Ed25519Keypair::generate();
        let addr: SocketAddr = "127.0.0.1:9999".parse().unwrap();

        let value = StorageNodeValue::new(&keypair, addr)
            .with_available_space(5000000)
            .with_used_space(2000000)
            .with_bags_count(100);

        let serialized = value.to_bytes().unwrap();
        assert!(!serialized.is_empty());

        // Verify key components are in the serialization
        assert!(serialized.starts_with(&keypair.public_key));
    }

    #[tokio::test]
    async fn test_sign_and_verify() {
        let keypair = Ed25519Keypair::generate();
        let addr: SocketAddr = "127.0.0.1:30303".parse().unwrap();

        let value = StorageNodeValue::new(&keypair, addr)
            .with_available_space(1000000)
            .with_used_space(500000);

        let signature = value.sign(&keypair).await.unwrap();

        assert_eq!(signature.public_key, keypair.public_key);
        assert!(value.verify_signature(&signature).is_ok());
    }

    #[tokio::test]
    async fn test_signature_validation_fails_on_tampering() {
        let keypair = Ed25519Keypair::generate();
        let addr: SocketAddr = "127.0.0.1:30303".parse().unwrap();

        let value = StorageNodeValue::new(&keypair, addr)
            .with_available_space(1000000);

        let mut signature = value.sign(&keypair).await.unwrap();

        // Tamper with the signature
        signature.signature[0] ^= 0xFF;

        // Verification should fail
        assert!(value.verify_signature(&signature).is_err());
    }

    #[test]
    fn test_flags_operations() {
        let keypair = Ed25519Keypair::generate();
        let addr: SocketAddr = "127.0.0.1:30303".parse().unwrap();

        let mut value = StorageNodeValue::new(&keypair, addr);

        // Initially no flags set
        assert!(!value.accepts_uploads());
        assert!(!value.accepts_downloads());
        assert!(!value.is_public());

        // Set uploads
        value.set_accepts_uploads(true);
        assert!(value.accepts_uploads());
        assert!(!value.accepts_downloads());

        // Set downloads
        value.set_accepts_downloads(true);
        assert!(value.accepts_uploads());
        assert!(value.accepts_downloads());

        // Set public
        value.set_public(true);
        assert!(value.accepts_uploads());
        assert!(value.accepts_downloads());
        assert!(value.is_public());

        // Unset uploads
        value.set_accepts_uploads(false);
        assert!(!value.accepts_uploads());
        assert!(value.accepts_downloads());
        assert!(value.is_public());
    }

    #[test]
    fn test_expiration_checking() {
        let keypair = Ed25519Keypair::generate();
        let addr: SocketAddr = "127.0.0.1:30303".parse().unwrap();

        // Create with default TTL
        let value = StorageNodeValue::new(&keypair, addr);
        assert!(!value.is_expired());
        assert!(value.time_to_expiry() > 0);

        // Create with very short TTL
        let mut value_short = StorageNodeValue::new(&keypair, addr);
        value_short.expires_at = 1; // Unix epoch + 1 second, definitely expired
        assert!(value_short.is_expired());
        assert!(value_short.time_to_expiry() < 0);
    }

    #[test]
    fn test_dht_key_derivation() {
        let keypair = Ed25519Keypair::generate();

        let key1 = StorageNodeValue::calculate_dht_key(&keypair.public_key);
        let key2 = StorageNodeValue::calculate_dht_key(&keypair.public_key);

        // Same provider ID should give same key
        assert_eq!(key1, key2);

        // Different provider ID should give different key
        let keypair2 = Ed25519Keypair::generate();
        let key3 = StorageNodeValue::calculate_dht_key(&keypair2.public_key);
        assert_ne!(key1, key3);
    }

    #[test]
    fn test_validation_available_vs_used_space() {
        let keypair = Ed25519Keypair::generate();
        let addr: SocketAddr = "127.0.0.1:30303".parse().unwrap();

        let value = StorageNodeValue::new(&keypair, addr)
            .with_available_space(100)
            .with_used_space(200); // More used than available

        let result = value.to_bytes();
        assert!(result.is_err());
    }

    #[test]
    fn test_validation_ttl_ranges() {
        let keypair = Ed25519Keypair::generate();
        let addr: SocketAddr = "127.0.0.1:30303".parse().unwrap();

        // TTL too small
        let mut value = StorageNodeValue::new(&keypair, addr);
        value.ttl = 30; // Less than MIN_TTL (60)
        let result = value.to_bytes();
        assert!(result.is_err());

        // TTL too large
        value.ttl = MAX_TTL + 1;
        let result = value.to_bytes();
        assert!(result.is_err());

        // Valid TTL ranges
        value.ttl = MIN_TTL;
        assert!(value.to_bytes().is_ok());

        value.ttl = MAX_TTL;
        assert!(value.to_bytes().is_ok());

        value.ttl = DEFAULT_TTL;
        assert!(value.to_bytes().is_ok());
    }

    #[test]
    fn test_invalid_address_rejected() {
        let keypair = Ed25519Keypair::generate();

        // Port 0 is invalid
        let value = StorageNodeValue::new(&keypair, "127.0.0.1:0".parse().unwrap());
        let result = value.to_bytes();
        assert!(result.is_err());
    }

    #[test]
    fn test_metadata_optional() {
        let keypair = Ed25519Keypair::generate();
        let addr: SocketAddr = "127.0.0.1:30303".parse().unwrap();

        // Without metadata
        let value1 = StorageNodeValue::new(&keypair, addr);
        assert!(value1.metadata.is_none());
        let bytes1 = value1.to_bytes().unwrap();

        // With metadata
        let metadata = StorageMetadata {
            region: Some("us-west".to_string()),
            bandwidth_kbps: 5000,
            download_latency_ms: 100,
            uptime_percent: 95,
            custom_data: vec![1, 2, 3],
        };
        let value2 = StorageNodeValue::new(&keypair, addr).with_metadata(metadata);
        assert!(value2.metadata.is_some());
        let bytes2 = value2.to_bytes().unwrap();

        // Serialization with metadata is larger
        assert!(bytes2.len() > bytes1.len());
    }

    #[tokio::test]
    async fn test_concurrent_signing() {
        let keypair = Ed25519Keypair::generate();
        let addr: SocketAddr = "127.0.0.1:30303".parse().unwrap();

        let value = StorageNodeValue::new(&keypair, addr)
            .with_available_space(1000000);

        // Sign multiple times concurrently
        let mut handles = vec![];

        for _ in 0..5 {
            let keypair_clone = keypair.clone();
            let value_clone = value.clone();

            let handle = tokio::spawn(async move {
                value_clone.sign(&keypair_clone).await
            });

            handles.push(handle);
        }

        for handle in handles {
            let result = handle.await.unwrap();
            assert!(result.is_ok());
        }
    }

    #[test]
    fn test_builder_construction() {
        let keypair = Ed25519Keypair::generate();
        let addr: SocketAddr = "192.168.1.50:8888".parse().unwrap();

        let value = StorageNodeValueBuilder::new(&keypair, addr)
            .available_space(5000000)
            .used_space(2000000)
            .bags_count(50)
            .max_chunk_size(512 * 1024)
            .ttl(7200)
            .flags(3)
            .build();

        assert_eq!(value.provider_id, keypair.public_key);
        assert_eq!(value.address, addr);
        assert_eq!(value.available_space, 5000000);
        assert_eq!(value.used_space, 2000000);
        assert_eq!(value.bags_count, 50);
        assert_eq!(value.max_chunk_size, 512 * 1024);
        assert_eq!(value.ttl, 7200);
        assert_eq!(value.flags, 3);
    }

    #[test]
    fn test_metadata_validation() {
        // Valid metadata
        let metadata = StorageMetadata {
            region: Some("eu-central".to_string()),
            bandwidth_kbps: 10000,
            download_latency_ms: 50,
            uptime_percent: 99,
            custom_data: vec![0u8; 100],
        };
        assert!(metadata.validate().is_ok());

        // Invalid: custom data too large
        let mut metadata = StorageMetadata::new();
        metadata.custom_data = vec![0u8; MAX_CUSTOM_DATA + 1];
        assert!(metadata.validate().is_err());

        // Invalid: uptime > 100
        let mut metadata = StorageMetadata::new();
        metadata.uptime_percent = 101;
        assert!(metadata.validate().is_err());
    }

    #[test]
    fn test_value_version_validation() {
        let keypair = Ed25519Keypair::generate();
        let addr: SocketAddr = "127.0.0.1:30303".parse().unwrap();

        let mut value = StorageNodeValue::new(&keypair, addr);
        value.version = 2; // Invalid version

        let result = value.to_bytes();
        assert!(result.is_err());
    }

    #[test]
    fn test_ipv4_and_ipv6_addresses() {
        let keypair = Ed25519Keypair::generate();

        // Test IPv4
        let addr_v4: SocketAddr = "192.168.1.1:30303".parse().unwrap();
        let value_v4 = StorageNodeValue::new(&keypair, addr_v4);
        assert!(value_v4.to_bytes().is_ok());

        // Test IPv6
        let addr_v6: SocketAddr = "[::1]:30303".parse().unwrap();
        let value_v6 = StorageNodeValue::new(&keypair, addr_v6);
        assert!(value_v6.to_bytes().is_ok());
    }

    #[test]
    fn test_storage_metadata_default() {
        let metadata = StorageMetadata::default();
        assert!(metadata.region.is_none());
        assert_eq!(metadata.bandwidth_kbps, 0);
        assert_eq!(metadata.download_latency_ms, 0);
        assert_eq!(metadata.uptime_percent, 100);
        assert!(metadata.custom_data.is_empty());
    }
}
