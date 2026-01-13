//! DHT reverse connection protocol for NAT traversal.
//!
//! This module implements the reverse connection protocol to enable communication
//! with nodes behind NAT (Network Address Translation). When a node cannot be
//! reached directly due to NAT, an intermediary node can help establish the connection.
//!
//! ## Protocol Overview
//!
//! 1. A node behind NAT registers with DHT nodes using `DhtRegisterReverseConnection`
//! 2. When another node wants to connect, it sends `DhtRequestReversePing` to an intermediary
//! 3. The intermediary forwards the ping to the target node
//! 4. The target node initiates an outbound connection to the requester
//!
//! ## TL Schema
//!
//! ```text
//! dht.getSignedAddressList = adnl.AddressList
//! dht.registerReverseConnection node:dht.node ttl:int signature:bytes = dht.Stored
//! dht.requestReversePing target:int256 signature:bytes client:int256 k:int = dht.ReversePingResult
//! ```

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::RwLock;
use tracing::{debug, trace};

use crate::error::{DhtError, Result};
use crate::node::{AdnlAddressList, DhtNode};
use crate::tl::{TlReader, TlWriter, DHT_NODES, DHT_STORED};

// ============================================================================
// TL Schema IDs for Reverse Connection Protocol
// ============================================================================

/// dht.getSignedAddressList = adnl.AddressList
/// Schema ID: 0xed4879a9
pub const DHT_GET_SIGNED_ADDRESS_LIST: u32 = 0xed4879a9;

/// dht.registerReverseConnection node:dht.node ttl:int signature:bytes = dht.Stored
/// Schema ID: 0xcba5c380
pub const DHT_REGISTER_REVERSE_CONNECTION: u32 = 0xcba5c380;

/// dht.requestReversePing target:int256 signature:bytes client:int256 k:int = dht.ReversePingResult
/// Schema ID: 0x4a42d5a5
pub const DHT_REQUEST_REVERSE_PING: u32 = 0x4a42d5a5;

/// dht.reversePingOk = dht.ReversePingResult
/// Schema ID: 0x93fadb8e
pub const DHT_REVERSE_PING_OK: u32 = 0x93fadb8e;

// ============================================================================
// Message Types
// ============================================================================

/// Request to get the signed address list from a DHT node.
///
/// This message requests the node's current signed address list,
/// which is useful for discovering how to reach a node directly.
#[derive(Debug, Clone)]
pub struct DhtGetSignedAddressList;

impl DhtGetSignedAddressList {
    /// Returns the TL schema ID.
    pub const fn schema_id() -> u32 {
        DHT_GET_SIGNED_ADDRESS_LIST
    }

    /// Serializes the message to TL format.
    pub fn to_tl(&self) -> Vec<u8> {
        let mut writer = TlWriter::new();
        writer.write_u32(DHT_GET_SIGNED_ADDRESS_LIST);
        writer.finish()
    }

    /// Deserializes from TL format.
    pub fn from_tl(data: &[u8]) -> Result<Self> {
        let mut reader = TlReader::new(data);
        let schema = reader.read_u32()?;
        if schema != DHT_GET_SIGNED_ADDRESS_LIST {
            return Err(DhtError::TlError(format!(
                "expected dht.getSignedAddressList (0x{:08x}), got 0x{:08x}",
                DHT_GET_SIGNED_ADDRESS_LIST, schema
            )));
        }
        Ok(Self)
    }
}

/// Request to register a reverse connection capability.
///
/// Nodes behind NAT send this message to DHT nodes to announce
/// that they can receive reverse connections. The TTL indicates
/// how long the registration is valid.
#[derive(Debug, Clone)]
pub struct DhtRegisterReverseConnection {
    /// The node registering for reverse connections.
    pub node: DhtNode,
    /// Time to live for this registration (seconds from now).
    pub ttl: u32,
    /// Signature over the registration data (64 bytes).
    pub signature: [u8; 64],
}

impl DhtRegisterReverseConnection {
    /// Returns the TL schema ID.
    pub const fn schema_id() -> u32 {
        DHT_REGISTER_REVERSE_CONNECTION
    }

    /// Creates a new registration request.
    pub fn new(node: DhtNode, ttl: u32) -> Self {
        Self {
            node,
            ttl,
            signature: [0u8; 64],
        }
    }

    /// Signs the registration with the given keypair.
    pub fn sign(&mut self, keypair: &ton_crypto::Ed25519Keypair) {
        let to_sign = self.to_tl_for_signing();
        let sig = keypair.sign(&to_sign);
        self.signature = sig;
    }

    /// Verifies the signature on this registration.
    pub fn verify_signature(&self) -> Result<()> {
        let to_verify = self.to_tl_for_signing();
        ton_crypto::verify_signature(&self.node.id, &to_verify, &self.signature).map_err(|e| {
            DhtError::SignatureVerificationFailed(format!(
                "reverse connection registration signature invalid: {}",
                e
            ))
        })
    }

    /// Serializes the message to TL format.
    pub fn to_tl(&self) -> Vec<u8> {
        let mut writer = TlWriter::new();
        writer.write_u32(DHT_REGISTER_REVERSE_CONNECTION);
        writer.write_raw(&self.node.to_tl());
        writer.write_u32(self.ttl);
        writer.write_bytes(&self.signature);
        writer.finish()
    }

    /// Serializes for signing (with zeroed signature).
    fn to_tl_for_signing(&self) -> Vec<u8> {
        let mut writer = TlWriter::new();
        writer.write_u32(DHT_REGISTER_REVERSE_CONNECTION);
        writer.write_raw(&self.node.to_tl());
        writer.write_u32(self.ttl);
        writer.write_bytes(&[0u8; 64]);
        writer.finish()
    }

    /// Deserializes from TL format.
    pub fn from_tl(data: &[u8]) -> Result<Self> {
        let mut reader = TlReader::new(data);

        let schema = reader.read_u32()?;
        if schema != DHT_REGISTER_REVERSE_CONNECTION {
            return Err(DhtError::TlError(format!(
                "expected dht.registerReverseConnection (0x{:08x}), got 0x{:08x}",
                DHT_REGISTER_REVERSE_CONNECTION, schema
            )));
        }

        // Read the node
        let node = DhtNode::from_reader(&mut reader)?;

        // Read TTL
        let ttl = reader.read_u32()?;

        // Read signature
        let sig_bytes = reader.read_bytes()?;
        if sig_bytes.len() != 64 {
            return Err(DhtError::TlError(format!(
                "signature must be 64 bytes, got {}",
                sig_bytes.len()
            )));
        }
        let mut signature = [0u8; 64];
        signature.copy_from_slice(&sig_bytes);

        Ok(Self {
            node,
            ttl,
            signature,
        })
    }
}

/// Request to ping a node through reverse connection.
///
/// When a node cannot reach a target directly, it sends this message
/// to an intermediary node that has a connection to the target.
/// The intermediary forwards the ping, causing the target to
/// initiate an outbound connection to the client.
#[derive(Debug, Clone)]
pub struct DhtRequestReversePing {
    /// The target node's ID (SHA256 of TL-serialized public key).
    pub target: [u8; 32],
    /// Signature proving the requester's identity.
    pub signature: [u8; 64],
    /// The client node's public key requesting the reverse ping.
    pub client: [u8; 32],
    /// Number of closest nodes to return if target not found.
    pub k: u32,
}

impl DhtRequestReversePing {
    /// Returns the TL schema ID.
    pub const fn schema_id() -> u32 {
        DHT_REQUEST_REVERSE_PING
    }

    /// Creates a new reverse ping request.
    pub fn new(target: [u8; 32], client: [u8; 32], k: u32) -> Self {
        Self {
            target,
            signature: [0u8; 64],
            client,
            k,
        }
    }

    /// Signs the request with the given keypair.
    pub fn sign(&mut self, keypair: &ton_crypto::Ed25519Keypair) {
        let to_sign = self.to_tl_for_signing();
        let sig = keypair.sign(&to_sign);
        self.signature = sig;
    }

    /// Verifies the signature on this request.
    pub fn verify_signature(&self) -> Result<()> {
        let to_verify = self.to_tl_for_signing();
        ton_crypto::verify_signature(&self.client, &to_verify, &self.signature).map_err(|e| {
            DhtError::SignatureVerificationFailed(format!(
                "reverse ping request signature invalid: {}",
                e
            ))
        })
    }

    /// Serializes the message to TL format.
    pub fn to_tl(&self) -> Vec<u8> {
        let mut writer = TlWriter::new();
        writer.write_u32(DHT_REQUEST_REVERSE_PING);
        writer.write_int256(&self.target);
        writer.write_bytes(&self.signature);
        writer.write_int256(&self.client);
        writer.write_i32(self.k as i32);
        writer.finish()
    }

    /// Serializes for signing (with zeroed signature).
    fn to_tl_for_signing(&self) -> Vec<u8> {
        let mut writer = TlWriter::new();
        writer.write_u32(DHT_REQUEST_REVERSE_PING);
        writer.write_int256(&self.target);
        writer.write_bytes(&[0u8; 64]);
        writer.write_int256(&self.client);
        writer.write_i32(self.k as i32);
        writer.finish()
    }

    /// Deserializes from TL format.
    pub fn from_tl(data: &[u8]) -> Result<Self> {
        let mut reader = TlReader::new(data);

        let schema = reader.read_u32()?;
        if schema != DHT_REQUEST_REVERSE_PING {
            return Err(DhtError::TlError(format!(
                "expected dht.requestReversePing (0x{:08x}), got 0x{:08x}",
                DHT_REQUEST_REVERSE_PING, schema
            )));
        }

        let target = reader.read_int256()?;

        let sig_bytes = reader.read_bytes()?;
        if sig_bytes.len() != 64 {
            return Err(DhtError::TlError(format!(
                "signature must be 64 bytes, got {}",
                sig_bytes.len()
            )));
        }
        let mut signature = [0u8; 64];
        signature.copy_from_slice(&sig_bytes);

        let client = reader.read_int256()?;
        let k = reader.read_i32()? as u32;

        Ok(Self {
            target,
            signature,
            client,
            k,
        })
    }
}

/// Result of a reverse ping request.
#[derive(Debug, Clone)]
pub enum ReversePingResult {
    /// The reverse ping was successful.
    Ok,
    /// Target not found, returning closest nodes.
    NotFound(Vec<DhtNode>),
}

impl ReversePingResult {
    /// Serializes the result to TL format.
    pub fn to_tl(&self) -> Vec<u8> {
        let mut writer = TlWriter::new();
        match self {
            ReversePingResult::Ok => {
                writer.write_u32(DHT_REVERSE_PING_OK);
            }
            ReversePingResult::NotFound(nodes) => {
                writer.write_u32(DHT_NODES);
                writer.write_i32(nodes.len() as i32);
                for node in nodes {
                    writer.write_raw(&node.to_tl());
                }
            }
        }
        writer.finish()
    }

    /// Deserializes from TL format.
    pub fn from_tl(data: &[u8]) -> Result<Self> {
        let mut reader = TlReader::new(data);
        let schema = reader.read_u32()?;

        match schema {
            DHT_REVERSE_PING_OK => Ok(ReversePingResult::Ok),
            DHT_NODES => {
                let count = reader.read_i32()? as usize;
                let mut nodes = Vec::with_capacity(count);
                for _ in 0..count {
                    nodes.push(DhtNode::from_reader(&mut reader)?);
                }
                Ok(ReversePingResult::NotFound(nodes))
            }
            _ => Err(DhtError::TlError(format!(
                "unexpected reverse ping result schema: 0x{:08x}",
                schema
            ))),
        }
    }
}

// ============================================================================
// Reverse Connection Manager
// ============================================================================

/// Entry for a registered reverse connection.
#[derive(Debug, Clone)]
struct ReverseConnectionEntry {
    /// The registered node.
    node: DhtNode,
    /// When the registration expires (absolute time).
    expires_at: Instant,
    /// Original TTL from the registration.
    #[allow(dead_code)]
    ttl: u32,
    /// Time when the registration was made.
    #[allow(dead_code)]
    registered_at: Instant,
}

impl ReverseConnectionEntry {
    /// Creates a new entry.
    fn new(node: DhtNode, ttl: u32) -> Self {
        Self {
            node,
            expires_at: Instant::now() + Duration::from_secs(ttl as u64),
            ttl,
            registered_at: Instant::now(),
        }
    }

    /// Returns true if the entry has expired.
    fn is_expired(&self) -> bool {
        Instant::now() >= self.expires_at
    }

    /// Returns the remaining TTL in seconds.
    #[allow(dead_code)]
    fn remaining_ttl(&self) -> u32 {
        let now = Instant::now();
        if now >= self.expires_at {
            0
        } else {
            (self.expires_at - now).as_secs() as u32
        }
    }
}

/// Statistics about the reverse connection manager.
#[derive(Debug, Clone, Default)]
pub struct ReverseConnectionStats {
    /// Total number of active registrations.
    pub active_registrations: usize,
    /// Total registrations ever received.
    pub total_registrations: u64,
    /// Total reverse pings processed.
    pub total_reverse_pings: u64,
    /// Successful reverse pings.
    pub successful_reverse_pings: u64,
    /// Failed reverse pings (target not found).
    pub failed_reverse_pings: u64,
}

/// Manager for reverse connection protocol.
///
/// This struct handles:
/// - Registration of nodes for reverse connections
/// - Tracking active registrations with TTL
/// - Routing reverse ping requests to registered nodes
///
/// # Example
///
/// ```rust,no_run
/// use ton_dht::reverse::ReverseConnectionManager;
///
/// async fn example() {
///     let manager = ReverseConnectionManager::new();
///
///     // Get statistics
///     let stats = manager.stats().await;
///     println!("Active registrations: {}", stats.active_registrations);
/// }
/// ```
pub struct ReverseConnectionManager {
    /// Registered reverse connections, keyed by node ID.
    registrations: Arc<RwLock<HashMap<[u8; 32], ReverseConnectionEntry>>>,
    /// Statistics about the manager.
    stats: Arc<RwLock<ReverseConnectionStats>>,
    /// Maximum TTL allowed for registrations (prevents abuse).
    max_ttl: u32,
    /// Maximum number of registrations (prevents memory exhaustion).
    max_registrations: usize,
}

impl ReverseConnectionManager {
    /// Default maximum TTL: 1 hour.
    pub const DEFAULT_MAX_TTL: u32 = 3600;

    /// Default maximum registrations: 10000.
    pub const DEFAULT_MAX_REGISTRATIONS: usize = 10000;

    /// Creates a new reverse connection manager with default settings.
    pub fn new() -> Self {
        Self {
            registrations: Arc::new(RwLock::new(HashMap::new())),
            stats: Arc::new(RwLock::new(ReverseConnectionStats::default())),
            max_ttl: Self::DEFAULT_MAX_TTL,
            max_registrations: Self::DEFAULT_MAX_REGISTRATIONS,
        }
    }

    /// Creates a manager with custom limits.
    pub fn with_limits(max_ttl: u32, max_registrations: usize) -> Self {
        Self {
            registrations: Arc::new(RwLock::new(HashMap::new())),
            stats: Arc::new(RwLock::new(ReverseConnectionStats::default())),
            max_ttl,
            max_registrations,
        }
    }

    /// Handles a reverse connection registration request.
    ///
    /// This validates the registration and stores it if valid.
    /// Returns an error if:
    /// - The signature is invalid
    /// - The TTL exceeds the maximum allowed
    /// - The registration limit has been reached
    pub async fn handle_register(
        &self,
        request: &DhtRegisterReverseConnection,
    ) -> Result<()> {
        // Verify the signature
        request.verify_signature()?;

        // Verify the node signature
        request.node.verify_signature()?;

        // Check TTL limits
        let effective_ttl = request.ttl.min(self.max_ttl);
        if effective_ttl == 0 {
            return Err(DhtError::InvalidValue("TTL cannot be zero".into()));
        }

        let node_id = request.node.node_id();

        let mut registrations = self.registrations.write().await;
        let mut stats = self.stats.write().await;

        // Check if we're at the limit (but allow updates to existing registrations)
        if registrations.len() >= self.max_registrations && !registrations.contains_key(&node_id) {
            // Try to evict expired entries first
            drop(registrations);
            drop(stats);
            self.evict_expired().await;
            registrations = self.registrations.write().await;
            stats = self.stats.write().await;

            if registrations.len() >= self.max_registrations {
                return Err(DhtError::BucketFull);
            }
        }

        // Create or update the registration
        let entry = ReverseConnectionEntry::new(request.node.clone(), effective_ttl);
        registrations.insert(node_id, entry);
        stats.total_registrations += 1;
        stats.active_registrations = registrations.len();

        debug!(
            "Registered reverse connection for node {:?} with TTL {}s",
            hex_encode(&node_id[..8]),
            effective_ttl
        );

        Ok(())
    }

    /// Handles a reverse ping request.
    ///
    /// If the target node is registered, this returns `ReversePingResult::Ok`
    /// and the caller should forward the ping to the target.
    /// If not found, returns the closest known nodes.
    pub async fn handle_reverse_ping(
        &self,
        request: &DhtRequestReversePing,
        closest_nodes: Vec<DhtNode>,
    ) -> Result<(ReversePingResult, Option<DhtNode>)> {
        // Verify the signature
        request.verify_signature()?;

        let mut stats = self.stats.write().await;
        stats.total_reverse_pings += 1;

        let registrations = self.registrations.read().await;

        // Look up the target
        if let Some(entry) = registrations.get(&request.target)
            && !entry.is_expired() {
                stats.successful_reverse_pings += 1;
                debug!(
                    "Reverse ping: found target {:?}",
                    hex_encode(&request.target[..8])
                );
                return Ok((ReversePingResult::Ok, Some(entry.node.clone())));
            }

        // Target not found or expired
        stats.failed_reverse_pings += 1;
        trace!(
            "Reverse ping: target {:?} not found",
            hex_encode(&request.target[..8])
        );

        Ok((ReversePingResult::NotFound(closest_nodes), None))
    }

    /// Looks up a registered node by ID.
    pub async fn get_registration(&self, node_id: &[u8; 32]) -> Option<DhtNode> {
        let registrations = self.registrations.read().await;
        registrations
            .get(node_id)
            .filter(|e| !e.is_expired())
            .map(|e| e.node.clone())
    }

    /// Returns all active registrations.
    pub async fn all_registrations(&self) -> Vec<DhtNode> {
        let registrations = self.registrations.read().await;
        registrations
            .values()
            .filter(|e| !e.is_expired())
            .map(|e| e.node.clone())
            .collect()
    }

    /// Removes a registration by node ID.
    pub async fn remove_registration(&self, node_id: &[u8; 32]) -> Option<DhtNode> {
        let mut registrations = self.registrations.write().await;
        let mut stats = self.stats.write().await;

        let result = registrations.remove(node_id).map(|e| e.node);
        stats.active_registrations = registrations.len();
        result
    }

    /// Evicts expired registrations.
    pub async fn evict_expired(&self) -> usize {
        let mut registrations = self.registrations.write().await;
        let initial_count = registrations.len();

        registrations.retain(|_, entry| !entry.is_expired());

        let evicted = initial_count - registrations.len();
        if evicted > 0 {
            debug!("Evicted {} expired reverse connection registrations", evicted);
        }

        let mut stats = self.stats.write().await;
        stats.active_registrations = registrations.len();

        evicted
    }

    /// Returns statistics about the manager.
    pub async fn stats(&self) -> ReverseConnectionStats {
        // Update active count before returning
        let registrations = self.registrations.read().await;
        let active = registrations.values().filter(|e| !e.is_expired()).count();
        drop(registrations);

        let mut stats = self.stats.write().await;
        stats.active_registrations = active;
        stats.clone()
    }

    /// Returns the number of active registrations.
    pub async fn active_count(&self) -> usize {
        let registrations = self.registrations.read().await;
        registrations.values().filter(|e| !e.is_expired()).count()
    }

    /// Starts a background task that periodically evicts expired entries.
    ///
    /// This spawns a Tokio task that runs every `interval` and cleans up
    /// expired registrations. The task runs until the manager is dropped.
    pub fn start_background_eviction(&self, interval: Duration) {
        let registrations = Arc::clone(&self.registrations);
        let stats = Arc::clone(&self.stats);

        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            loop {
                ticker.tick().await;

                let mut regs = registrations.write().await;
                let initial = regs.len();
                regs.retain(|_, e| !e.is_expired());
                let evicted = initial - regs.len();

                if evicted > 0 {
                    let mut s = stats.write().await;
                    s.active_registrations = regs.len();
                    debug!(
                        "Background eviction: removed {} expired registrations",
                        evicted
                    );
                }
            }
        });
    }
}

impl Default for ReverseConnectionManager {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for ReverseConnectionManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReverseConnectionManager")
            .field("max_ttl", &self.max_ttl)
            .field("max_registrations", &self.max_registrations)
            .finish()
    }
}

// ============================================================================
// Handlers for Message Processing
// ============================================================================

/// Processes an incoming DHT message and returns the appropriate response.
///
/// This function handles:
/// - `DhtGetSignedAddressList`: Returns the node's signed address list
/// - `DhtRegisterReverseConnection`: Registers a reverse connection
/// - `DhtRequestReversePing`: Handles reverse ping requests
pub async fn handle_reverse_connection_message(
    manager: &ReverseConnectionManager,
    data: &[u8],
    local_addr_list: &AdnlAddressList,
    closest_nodes_fn: impl Fn(&[u8; 32], u32) -> Vec<DhtNode>,
) -> Result<Vec<u8>> {
    if data.len() < 4 {
        return Err(DhtError::TlError("message too short".into()));
    }

    let reader = TlReader::new(data);
    let schema = reader.peek_u32()?;

    match schema {
        DHT_GET_SIGNED_ADDRESS_LIST => {
            // Return the local address list
            debug!("Handling dht.getSignedAddressList request");
            Ok(local_addr_list.to_tl())
        }

        DHT_REGISTER_REVERSE_CONNECTION => {
            let request = DhtRegisterReverseConnection::from_tl(data)?;
            manager.handle_register(&request).await?;

            // Return dht.stored
            let mut response = TlWriter::new();
            response.write_u32(DHT_STORED);
            Ok(response.finish())
        }

        DHT_REQUEST_REVERSE_PING => {
            let request = DhtRequestReversePing::from_tl(data)?;
            let closest = closest_nodes_fn(&request.target, request.k);
            let (result, _target_node) = manager.handle_reverse_ping(&request, closest).await?;

            // If we found the target, the caller should initiate the reverse ping
            // For now, just return the result
            Ok(result.to_tl())
        }

        _ => Err(DhtError::TlError(format!(
            "unknown reverse connection message: 0x{:08x}",
            schema
        ))),
    }
}

/// Helper function for hex encoding (for debug output).
fn hex_encode(data: &[u8]) -> String {
    data.iter().map(|b| format!("{:02x}", b)).collect()
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use ton_crypto::Ed25519Keypair;
    use crate::node::AdnlAddress;

    fn create_test_node(keypair: &Ed25519Keypair) -> DhtNode {
        let addr = AdnlAddress::udp(Ipv4Addr::new(127, 0, 0, 1), 30303);
        let addr_list = AdnlAddressList::with_address(addr);
        let mut node = DhtNode::with_current_version(keypair.public_key, addr_list);
        node.sign(keypair);
        node
    }

    #[test]
    fn test_get_signed_address_list_roundtrip() {
        let msg = DhtGetSignedAddressList;
        let tl = msg.to_tl();

        assert_eq!(tl.len(), 4);
        assert_eq!(
            u32::from_le_bytes([tl[0], tl[1], tl[2], tl[3]]),
            DHT_GET_SIGNED_ADDRESS_LIST
        );

        let decoded = DhtGetSignedAddressList::from_tl(&tl).unwrap();
        // It's a unit struct, just verify it parses
        let _ = decoded;
    }

    #[test]
    fn test_register_reverse_connection_roundtrip() {
        let keypair = Ed25519Keypair::generate();
        let node = create_test_node(&keypair);

        let mut msg = DhtRegisterReverseConnection::new(node.clone(), 3600);
        msg.sign(&keypair);

        let tl = msg.to_tl();
        let decoded = DhtRegisterReverseConnection::from_tl(&tl).unwrap();

        assert_eq!(decoded.ttl, 3600);
        assert_eq!(decoded.signature, msg.signature);
        assert_eq!(decoded.node.id, node.id);

        // Verify the signature
        assert!(decoded.verify_signature().is_ok());
    }

    #[test]
    fn test_request_reverse_ping_roundtrip() {
        let client_keypair = Ed25519Keypair::generate();
        let target = [42u8; 32];

        let mut msg = DhtRequestReversePing::new(target, client_keypair.public_key, 10);
        msg.sign(&client_keypair);

        let tl = msg.to_tl();
        let decoded = DhtRequestReversePing::from_tl(&tl).unwrap();

        assert_eq!(decoded.target, target);
        assert_eq!(decoded.client, client_keypair.public_key);
        assert_eq!(decoded.k, 10);
        assert_eq!(decoded.signature, msg.signature);

        // Verify the signature
        assert!(decoded.verify_signature().is_ok());
    }

    #[test]
    fn test_reverse_ping_result_ok() {
        let result = ReversePingResult::Ok;
        let tl = result.to_tl();
        let decoded = ReversePingResult::from_tl(&tl).unwrap();

        match decoded {
            ReversePingResult::Ok => {}
            _ => panic!("Expected Ok result"),
        }
    }

    #[test]
    fn test_reverse_ping_result_not_found() {
        let keypair = Ed25519Keypair::generate();
        let node = create_test_node(&keypair);

        let result = ReversePingResult::NotFound(vec![node.clone()]);
        let tl = result.to_tl();
        let decoded = ReversePingResult::from_tl(&tl).unwrap();

        match decoded {
            ReversePingResult::NotFound(nodes) => {
                assert_eq!(nodes.len(), 1);
                assert_eq!(nodes[0].id, keypair.public_key);
            }
            _ => panic!("Expected NotFound result"),
        }
    }

    #[tokio::test]
    async fn test_manager_registration() {
        let manager = ReverseConnectionManager::new();
        let keypair = Ed25519Keypair::generate();
        let node = create_test_node(&keypair);

        let mut request = DhtRegisterReverseConnection::new(node.clone(), 60);
        request.sign(&keypair);

        // Register
        manager.handle_register(&request).await.unwrap();

        // Check stats
        let stats = manager.stats().await;
        assert_eq!(stats.active_registrations, 1);
        assert_eq!(stats.total_registrations, 1);

        // Lookup
        let node_id = node.node_id();
        let found = manager.get_registration(&node_id).await;
        assert!(found.is_some());
        assert_eq!(found.unwrap().id, keypair.public_key);
    }

    #[tokio::test]
    async fn test_manager_reverse_ping_found() {
        let manager = ReverseConnectionManager::new();
        let keypair = Ed25519Keypair::generate();
        let node = create_test_node(&keypair);
        let node_id = node.node_id();

        // Register the node
        let mut reg = DhtRegisterReverseConnection::new(node.clone(), 60);
        reg.sign(&keypair);
        manager.handle_register(&reg).await.unwrap();

        // Request reverse ping
        let client_keypair = Ed25519Keypair::generate();
        let mut ping = DhtRequestReversePing::new(node_id, client_keypair.public_key, 10);
        ping.sign(&client_keypair);

        let (result, target_node) = manager.handle_reverse_ping(&ping, vec![]).await.unwrap();

        match result {
            ReversePingResult::Ok => {}
            _ => panic!("Expected Ok result"),
        }
        assert!(target_node.is_some());

        let stats = manager.stats().await;
        assert_eq!(stats.successful_reverse_pings, 1);
    }

    #[tokio::test]
    async fn test_manager_reverse_ping_not_found() {
        let manager = ReverseConnectionManager::new();
        let client_keypair = Ed25519Keypair::generate();
        let target = [99u8; 32]; // Non-existent target

        let mut ping = DhtRequestReversePing::new(target, client_keypair.public_key, 10);
        ping.sign(&client_keypair);

        let (result, target_node) = manager.handle_reverse_ping(&ping, vec![]).await.unwrap();

        match result {
            ReversePingResult::NotFound(nodes) => {
                assert!(nodes.is_empty());
            }
            _ => panic!("Expected NotFound result"),
        }
        assert!(target_node.is_none());

        let stats = manager.stats().await;
        assert_eq!(stats.failed_reverse_pings, 1);
    }

    #[tokio::test]
    async fn test_manager_eviction() {
        let manager = ReverseConnectionManager::with_limits(1, 100); // 1 second max TTL
        let keypair = Ed25519Keypair::generate();
        let node = create_test_node(&keypair);

        let mut request = DhtRegisterReverseConnection::new(node.clone(), 1);
        request.sign(&keypair);

        manager.handle_register(&request).await.unwrap();
        assert_eq!(manager.active_count().await, 1);

        // Wait for expiration
        tokio::time::sleep(Duration::from_millis(1100)).await;

        // Evict
        let evicted = manager.evict_expired().await;
        assert_eq!(evicted, 1);
        assert_eq!(manager.active_count().await, 0);
    }

    #[tokio::test]
    async fn test_manager_max_registrations() {
        let manager = ReverseConnectionManager::with_limits(3600, 2); // Max 2 registrations

        // Register 2 nodes
        for _ in 0..2 {
            let keypair = Ed25519Keypair::generate();
            let node = create_test_node(&keypair);
            let mut request = DhtRegisterReverseConnection::new(node, 60);
            request.sign(&keypair);
            manager.handle_register(&request).await.unwrap();
        }

        // Try to register a third (should fail)
        let keypair3 = Ed25519Keypair::generate();
        let node3 = create_test_node(&keypair3);
        let mut request3 = DhtRegisterReverseConnection::new(node3, 60);
        request3.sign(&keypair3);

        let result = manager.handle_register(&request3).await;
        assert!(matches!(result, Err(DhtError::BucketFull)));
    }

    #[test]
    fn test_invalid_signature() {
        let keypair = Ed25519Keypair::generate();
        let node = create_test_node(&keypair);

        let mut request = DhtRegisterReverseConnection::new(node, 3600);
        // Don't sign - should have invalid signature
        request.signature = [0u8; 64];

        let result = request.verify_signature();
        assert!(result.is_err());
    }

    #[test]
    fn test_schema_ids() {
        assert_eq!(DHT_GET_SIGNED_ADDRESS_LIST, 0xed4879a9);
        assert_eq!(DHT_REGISTER_REVERSE_CONNECTION, 0xcba5c380);
        assert_eq!(DHT_REQUEST_REVERSE_PING, 0x4a42d5a5);
        assert_eq!(DHT_REVERSE_PING_OK, 0x93fadb8e);
    }
}
