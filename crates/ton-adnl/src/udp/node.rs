//! ADNL UDP node implementation.
//!
//! An ADNL node is a participant in the TON network that can communicate
//! with multiple peers over UDP. It manages:
//!
//! - Local identity (keypair)
//! - UDP socket
//! - Multiple peer connections
//! - Channel establishment
//! - Message routing

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::num::NonZeroU32;
use std::sync::Arc;
use std::time::Duration;

use governor::{Quota, RateLimiter};
use governor::clock::DefaultClock;
use governor::state::{InMemoryState, NotKeyed};
use governor::state::keyed::DefaultKeyedStateStore;

use tokio::net::UdpSocket;
use tokio::sync::oneshot;
use tokio::time::timeout;
use tracing::{debug, trace, warn};

use ton_crypto::{
    ed25519::Ed25519Keypair,
    keys::calculate_key_id,
    x25519::X25519Keypair,
};

use crate::error::{AdnlError, Result};

use super::packet::{
    AdnlPacketContents, decode_udp_packet,
    encode_udp_packet, MAX_UDP_PACKET_SIZE,
};
use super::peer::AdnlPeer;
use super::AdnlMessage;

/// Default timeout for operations.
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// Interval for maintenance tasks (cleanup, keepalive).
#[allow(dead_code)]
const MAINTENANCE_INTERVAL: Duration = Duration::from_secs(5);

/// Maximum idle time before disconnecting a peer.
const MAX_IDLE_TIME: Duration = Duration::from_secs(60);

/// Default rate limit: packets per second per IP address.
const DEFAULT_RATE_LIMIT_PPS: u32 = 100;

/// Type alias for the keyed rate limiter (by IP address).
type KeyedRateLimiter = RateLimiter<IpAddr, DefaultKeyedStateStore<IpAddr>, DefaultClock>;

/// Type alias for a non-keyed rate limiter (global).
#[allow(dead_code)]
type GlobalRateLimiter = RateLimiter<NotKeyed, InMemoryState, DefaultClock>;

/// Configuration for rate limiting.
#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    /// Maximum packets per second per IP address.
    pub packets_per_second: u32,
    /// Whether rate limiting is enabled.
    pub enabled: bool,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            packets_per_second: DEFAULT_RATE_LIMIT_PPS,
            enabled: true,
        }
    }
}

impl RateLimitConfig {
    /// Creates a new rate limit configuration.
    pub fn new(packets_per_second: u32) -> Self {
        Self {
            packets_per_second,
            enabled: true,
        }
    }

    /// Creates a disabled rate limit configuration.
    pub fn disabled() -> Self {
        Self {
            packets_per_second: DEFAULT_RATE_LIMIT_PPS,
            enabled: false,
        }
    }
}

/// An ADNL UDP node.
///
/// This is the main entry point for UDP ADNL communication.
/// It manages a local identity, UDP socket, and multiple peer connections.
pub struct AdnlNode {
    /// Our identity keypair (Ed25519 for signing, also used for X25519 ECDH).
    keypair: Ed25519Keypair,
    /// Our X25519 keypair for ECDH (derived from Ed25519).
    x25519_keypair: X25519Keypair,
    /// Our key ID.
    key_id: [u8; 32],
    /// The UDP socket.
    socket: Arc<UdpSocket>,
    /// Connected peers, keyed by their key ID.
    peers: HashMap<[u8; 32], AdnlPeer>,
    /// Channel key IDs mapped to peer key IDs.
    channel_to_peer: HashMap<[u8; 32], [u8; 32]>,
    /// Address to peer key ID mapping.
    addr_to_peer: HashMap<SocketAddr, [u8; 32]>,
    /// Operation timeout.
    timeout: Duration,
    /// Receive buffer.
    recv_buffer: Vec<u8>,
    /// Rate limiter keyed by IP address.
    rate_limiter: Option<Arc<KeyedRateLimiter>>,
    /// Rate limit configuration.
    rate_limit_config: RateLimitConfig,
}

impl AdnlNode {
    /// Creates a new ADNL node bound to the specified address.
    pub async fn bind(addr: SocketAddr) -> Result<Self> {
        let socket = UdpSocket::bind(addr).await.map_err(AdnlError::Io)?;
        let keypair = Ed25519Keypair::generate();

        Self::with_keypair(socket, keypair)
    }

    /// Creates a new ADNL node with a specific keypair.
    pub fn with_keypair(socket: UdpSocket, keypair: Ed25519Keypair) -> Result<Self> {
        Self::with_keypair_and_config(socket, keypair, RateLimitConfig::default())
    }

    /// Creates a new ADNL node with a specific keypair and rate limit configuration.
    pub fn with_keypair_and_config(
        socket: UdpSocket,
        keypair: Ed25519Keypair,
        rate_limit_config: RateLimitConfig,
    ) -> Result<Self> {
        let key_id = calculate_key_id(&keypair.public_key);
        let x25519_keypair = X25519Keypair::from_private_key(*keypair.private_key_bytes());

        let rate_limiter = if rate_limit_config.enabled {
            Some(Arc::new(Self::create_rate_limiter(rate_limit_config.packets_per_second)))
        } else {
            None
        };

        Ok(Self {
            keypair,
            x25519_keypair,
            key_id,
            socket: Arc::new(socket),
            peers: HashMap::new(),
            channel_to_peer: HashMap::new(),
            addr_to_peer: HashMap::new(),
            timeout: DEFAULT_TIMEOUT,
            recv_buffer: vec![0u8; MAX_UDP_PACKET_SIZE],
            rate_limiter,
            rate_limit_config,
        })
    }

    /// Creates a keyed rate limiter with the specified packets per second limit.
    fn create_rate_limiter(packets_per_second: u32) -> KeyedRateLimiter {
        let quota = Quota::per_second(
            NonZeroU32::new(packets_per_second).unwrap_or(NonZeroU32::new(DEFAULT_RATE_LIMIT_PPS).unwrap())
        );
        RateLimiter::keyed(quota)
    }

    /// Returns the local address.
    pub fn local_addr(&self) -> Result<SocketAddr> {
        self.socket.local_addr().map_err(AdnlError::Io)
    }

    /// Returns our public key.
    pub fn public_key(&self) -> &[u8; 32] {
        &self.keypair.public_key
    }

    /// Returns our key ID.
    pub fn key_id(&self) -> &[u8; 32] {
        &self.key_id
    }

    /// Returns the peer key ID for a given public key.
    pub fn get_peer_id(&self, pubkey: &[u8; 32]) -> [u8; 32] {
        calculate_key_id(pubkey)
    }

    /// Sets the operation timeout.
    pub fn set_timeout(&mut self, timeout: Duration) {
        self.timeout = timeout;
    }

    /// Returns the current rate limit configuration.
    pub fn rate_limit_config(&self) -> &RateLimitConfig {
        &self.rate_limit_config
    }

    /// Sets the rate limit configuration.
    ///
    /// This recreates the rate limiter with the new configuration.
    pub fn set_rate_limit_config(&mut self, config: RateLimitConfig) {
        self.rate_limiter = if config.enabled {
            Some(Arc::new(Self::create_rate_limiter(config.packets_per_second)))
        } else {
            None
        };
        self.rate_limit_config = config;
    }

    /// Checks if a packet from the given IP address should be rate limited.
    ///
    /// Returns `true` if the packet is allowed, `false` if it should be dropped.
    pub fn check_rate_limit(&self, ip: &IpAddr) -> bool {
        match &self.rate_limiter {
            Some(limiter) => limiter.check_key(ip).is_ok(),
            None => true, // Rate limiting disabled, allow all
        }
    }

    /// Adds a new peer.
    pub async fn add_peer(&mut self, addr: SocketAddr, pubkey: &[u8; 32]) -> Result<()> {
        let peer_id = calculate_key_id(pubkey);

        if self.peers.contains_key(&peer_id) {
            return Ok(()); // Already added
        }

        let peer = AdnlPeer::new(addr, pubkey);
        self.peers.insert(peer_id, peer);
        self.addr_to_peer.insert(addr, peer_id);

        debug!("Added peer {} at {}", hex::encode(&peer_id[..8]), addr);

        Ok(())
    }

    /// Removes a peer.
    pub fn remove_peer(&mut self, peer_id: &[u8; 32]) {
        if let Some(peer) = self.peers.remove(peer_id) {
            self.addr_to_peer.remove(&peer.addr());

            // Remove channel mapping if any
            if let Some(channel) = peer.channel() {
                self.channel_to_peer.remove(channel.out_channel_id());
            }

            debug!("Removed peer {}", hex::encode(&peer_id[..8]));
        }
    }

    /// Returns a reference to a peer.
    pub fn peer(&self, peer_id: &[u8; 32]) -> Option<&AdnlPeer> {
        self.peers.get(peer_id)
    }

    /// Returns a mutable reference to a peer.
    pub fn peer_mut(&mut self, peer_id: &[u8; 32]) -> Option<&mut AdnlPeer> {
        self.peers.get_mut(peer_id)
    }

    /// Returns all peer IDs.
    pub fn peer_ids(&self) -> Vec<[u8; 32]> {
        self.peers.keys().copied().collect()
    }

    /// Establishes a channel with a peer.
    pub async fn establish_channel(&mut self, peer_id: &[u8; 32]) -> Result<()> {
        let peer = self.peers.get_mut(peer_id).ok_or_else(|| {
            AdnlError::InvalidPacket("peer not found".into())
        })?;

        // Initiate channel
        let create_msg = peer.initiate_channel();
        let packet = peer.create_packet(create_msg, true, &self.keypair.public_key);

        // Send the packet
        self.send_initial_packet(peer_id, &packet).await?;

        debug!("Initiated channel with peer {}", hex::encode(&peer_id[..8]));

        Ok(())
    }

    /// Sends a query to a peer and waits for a response.
    pub async fn send_query(&mut self, peer_id: &[u8; 32], data: &[u8]) -> Result<Vec<u8>> {
        let query_id = generate_query_id();

        // Create response channel
        let (tx, rx) = oneshot::channel();

        // Check if we need to establish a channel first
        let needs_channel = {
            let peer = self.peers.get(peer_id).ok_or_else(|| {
                AdnlError::InvalidPacket("peer not found".into())
            })?;
            !peer.has_channel()
        };

        if needs_channel {
            self.establish_channel(peer_id).await?;
            self.wait_for_channel(peer_id).await?;
        }

        // Create and send query
        let packet = {
            let peer = self.peers.get_mut(peer_id).ok_or_else(|| {
                AdnlError::InvalidPacket("peer not found".into())
            })?;
            let query_msg = peer.create_query_with_response(query_id, data.to_vec(), tx)?;
            peer.create_packet(query_msg, false, &self.keypair.public_key)
        };

        self.send_channel_packet(peer_id, &packet).await?;

        // Wait for response
        let response = timeout(self.timeout, rx)
            .await
            .map_err(|_| AdnlError::QueryTimeout)?
            .map_err(|_| AdnlError::NoResponse)?;

        Ok(response)
    }

    /// Sends a custom message (no response expected).
    pub async fn send_custom(&mut self, peer_id: &[u8; 32], data: &[u8]) -> Result<()> {
        let (packet, has_channel) = {
            let peer = self.peers.get_mut(peer_id).ok_or_else(|| {
                AdnlError::InvalidPacket("peer not found".into())
            })?;

            let message = AdnlMessage::Custom { data: data.to_vec() };
            let has_channel = peer.has_channel();
            let packet = peer.create_packet(message, !has_channel, &self.keypair.public_key);
            (packet, has_channel)
        };

        if has_channel {
            self.send_channel_packet(peer_id, &packet).await
        } else {
            self.send_initial_packet(peer_id, &packet).await
        }
    }

    /// Receives and processes the next incoming packet.
    ///
    /// Returns the message and the sender's peer ID.
    /// Packets that exceed the rate limit are silently dropped.
    pub async fn recv(&mut self) -> Result<(AdnlMessage, [u8; 32])> {
        loop {
            let (len, addr) = self.socket.recv_from(&mut self.recv_buffer).await?;

            // Check rate limit before processing
            if !self.check_rate_limit(&addr.ip()) {
                trace!("Rate limited packet from {}, dropping", addr);
                continue;
            }

            // Copy the data to avoid borrow issues
            let data = self.recv_buffer[..len].to_vec();

            trace!("Received {} bytes from {}", len, addr);

            match self.process_packet(&data, addr).await {
                Ok(Some((msg, peer_id))) => return Ok((msg, peer_id)),
                Ok(None) => continue, // Internal message (like channel handshake)
                Err(e) => {
                    warn!("Error processing packet from {}: {}", addr, e);
                    continue;
                }
            }
        }
    }

    /// Receives with timeout.
    pub async fn recv_timeout(&mut self, timeout_duration: Duration) -> Result<(AdnlMessage, [u8; 32])> {
        timeout(timeout_duration, self.recv())
            .await
            .map_err(|_| AdnlError::QueryTimeout)?
    }

    /// Processes an incoming packet.
    async fn process_packet(
        &mut self,
        data: &[u8],
        addr: SocketAddr,
    ) -> Result<Option<(AdnlMessage, [u8; 32])>> {
        if data.len() < 64 {
            return Err(AdnlError::InvalidPacket("packet too short".into()));
        }

        let key_id: [u8; 32] = data[..32].try_into().unwrap();

        // Check if this is an initial packet to us
        if key_id == self.key_id {
            return self.process_initial_packet(data, addr).await;
        }

        // Check if this is a channel packet
        if let Some(&peer_id) = self.channel_to_peer.get(&key_id) {
            return self.process_channel_packet(data, &peer_id).await;
        }

        // Unknown key ID - might be from a new peer
        Err(AdnlError::InvalidPacket("unknown key ID".into()))
    }

    /// Processes an initial (non-channel) packet.
    async fn process_initial_packet(
        &mut self,
        data: &[u8],
        addr: SocketAddr,
    ) -> Result<Option<(AdnlMessage, [u8; 32])>> {
        let (_, content) = decode_udp_packet(
            data,
            &self.key_id,
            &self.x25519_keypair.private_key,
        )?;

        // Get sender's public key from the packet
        let sender_pubkey = content.from.ok_or_else(|| {
            AdnlError::InvalidPacket("initial packet missing 'from' field".into())
        })?;

        let peer_id = calculate_key_id(&sender_pubkey);

        // Add peer if not known
        if let std::collections::hash_map::Entry::Vacant(e) = self.peers.entry(peer_id) {
            let peer = AdnlPeer::new(addr, &sender_pubkey);
            e.insert(peer);
            self.addr_to_peer.insert(addr, peer_id);
            debug!("Added new peer {} from {}", hex::encode(&peer_id[..8]), addr);
        }

        // Process the message
        self.process_message(&content, &peer_id).await
    }

    /// Processes a channel packet.
    async fn process_channel_packet(
        &mut self,
        data: &[u8],
        peer_id: &[u8; 32],
    ) -> Result<Option<(AdnlMessage, [u8; 32])>> {
        // Extract checksum and encrypted data
        let checksum: [u8; 32] = data[32..64].try_into().unwrap();
        let encrypted = &data[64..];

        // Get the decrypted content
        let (_decrypted, content) = {
            let peer = self.peers.get_mut(peer_id).ok_or_else(|| {
                AdnlError::InvalidPacket("peer not found".into())
            })?;

            let channel = peer.channel_mut().ok_or_else(|| {
                AdnlError::InvalidPacket("channel not found".into())
            })?;

            // Decrypt using channel cipher
            channel.reset_ciphers();
            let decrypted = channel.decrypt(encrypted);

            // Verify checksum
            let computed_checksum = ton_crypto::sha256::sha256(&decrypted);
            if computed_checksum != checksum {
                return Err(AdnlError::ChecksumMismatch);
            }

            let content = AdnlPacketContents::decode(&decrypted)?;

            // Update peer state
            peer.process_packet(&content);

            (decrypted, content)
        };

        // Process the message
        self.process_message(&content, peer_id).await
    }

    /// Processes the message content.
    async fn process_message(
        &mut self,
        content: &AdnlPacketContents,
        peer_id: &[u8; 32],
    ) -> Result<Option<(AdnlMessage, [u8; 32])>> {
        // Handle single message
        if let Some(ref message) = content.message {
            return self.handle_message(message.clone(), peer_id).await;
        }

        // Handle multiple messages
        if let Some(ref messages) = content.messages {
            for message in messages {
                if let Some(result) = self.handle_message(message.clone(), peer_id).await? {
                    return Ok(Some(result));
                }
            }
        }

        Ok(None)
    }

    /// Handles a single message.
    async fn handle_message(
        &mut self,
        message: AdnlMessage,
        peer_id: &[u8; 32],
    ) -> Result<Option<(AdnlMessage, [u8; 32])>> {
        match message {
            AdnlMessage::CreateChannel { key, date } => {
                self.handle_create_channel(peer_id, &key, date).await?;
                Ok(None)
            }
            AdnlMessage::ConfirmChannel { key, peer_key, date } => {
                self.handle_confirm_channel(peer_id, &key, &peer_key, date)?;
                Ok(None)
            }
            AdnlMessage::Answer { query_id, answer } => {
                let peer = self.peers.get_mut(peer_id).ok_or_else(|| {
                    AdnlError::InvalidPacket("peer not found".into())
                })?;
                peer.handle_answer(&query_id, answer);
                Ok(None)
            }
            AdnlMessage::Part { hash, total_size, offset, data } => {
                let peer = self.peers.get_mut(peer_id).ok_or_else(|| {
                    AdnlError::InvalidPacket("peer not found".into())
                })?;
                if let Some(complete) = peer.handle_part(&hash, total_size, offset, data) {
                    // TODO: Decode and process the complete message
                    trace!("Received complete fragmented message: {} bytes", complete.len());
                }
                Ok(None)
            }
            msg @ AdnlMessage::Query { .. } | msg @ AdnlMessage::Custom { .. } => {
                Ok(Some((msg, *peer_id)))
            }
        }
    }

    /// Handles a createChannel message.
    async fn handle_create_channel(
        &mut self,
        peer_id: &[u8; 32],
        key: &[u8; 32],
        date: i32,
    ) -> Result<()> {
        let packet = {
            let peer = self.peers.get_mut(peer_id).ok_or_else(|| {
                AdnlError::InvalidPacket("peer not found".into())
            })?;

            let confirm_msg = peer.handle_create_channel(key, date);

            // Store channel mapping
            if let Some(channel) = peer.channel() {
                self.channel_to_peer.insert(*channel.out_channel_id(), *peer_id);
            }

            // Create packet
            peer.create_packet(confirm_msg, true, &self.keypair.public_key)
        };

        // Send confirmation
        self.send_initial_packet(peer_id, &packet).await?;

        debug!("Confirmed channel with peer {}", hex::encode(&peer_id[..8]));

        Ok(())
    }

    /// Handles a confirmChannel message.
    fn handle_confirm_channel(
        &mut self,
        peer_id: &[u8; 32],
        key: &[u8; 32],
        peer_key: &[u8; 32],
        date: i32,
    ) -> Result<()> {
        let peer = self.peers.get_mut(peer_id).ok_or_else(|| {
            AdnlError::InvalidPacket("peer not found".into())
        })?;

        peer.handle_confirm_channel(key, peer_key, date)?;

        // Store channel mapping
        if let Some(channel) = peer.channel() {
            self.channel_to_peer.insert(*channel.out_channel_id(), *peer_id);
        }

        debug!("Channel established with peer {}", hex::encode(&peer_id[..8]));

        Ok(())
    }

    /// Sends an initial (non-channel) packet.
    async fn send_initial_packet(
        &self,
        peer_id: &[u8; 32],
        content: &AdnlPacketContents,
    ) -> Result<()> {
        let peer = self.peers.get(peer_id).ok_or_else(|| {
            AdnlError::InvalidPacket("peer not found".into())
        })?;

        let packet = encode_udp_packet(
            content,
            peer.peer_pubkey(),
            &self.x25519_keypair.private_key,
            &self.x25519_keypair.public_key,
        );

        self.socket.send_to(&packet, peer.addr()).await?;

        trace!("Sent {} bytes to {}", packet.len(), peer.addr());

        Ok(())
    }

    /// Sends a channel packet.
    async fn send_channel_packet(
        &mut self,
        peer_id: &[u8; 32],
        content: &AdnlPacketContents,
    ) -> Result<()> {
        // Build the packet with peer data
        let (packet, addr) = {
            let peer = self.peers.get_mut(peer_id).ok_or_else(|| {
                AdnlError::InvalidPacket("peer not found".into())
            })?;

            let addr = peer.addr();

            let channel = peer.channel_mut().ok_or_else(|| {
                AdnlError::InvalidPacket("no channel established".into())
            })?;

            let channel_id = *channel.out_channel_id();

            // Encode content
            let encoded = content.encode();
            let checksum = ton_crypto::sha256::sha256(&encoded);

            // Encrypt
            channel.reset_ciphers();
            let encrypted = channel.encrypt(&encoded);

            // Build packet
            let mut packet = Vec::with_capacity(64 + encrypted.len());
            packet.extend_from_slice(&channel_id);
            packet.extend_from_slice(&checksum);
            packet.extend_from_slice(&encrypted);

            (packet, addr)
        };

        self.socket.send_to(&packet, addr).await?;

        trace!("Sent {} bytes (channel) to {}", packet.len(), addr);

        Ok(())
    }

    /// Waits for a channel to be established.
    async fn wait_for_channel(&mut self, peer_id: &[u8; 32]) -> Result<()> {
        let deadline = tokio::time::Instant::now() + self.timeout;

        loop {
            if tokio::time::Instant::now() > deadline {
                return Err(AdnlError::QueryTimeout);
            }

            // Check if channel is ready
            if let Some(peer) = self.peers.get(peer_id) {
                if peer.has_channel() {
                    return Ok(());
                }
            } else {
                return Err(AdnlError::InvalidPacket("peer not found".into()));
            }

            // Receive and process packets until channel is ready
            let recv_timeout = Duration::from_millis(100);
            match timeout(recv_timeout, self.socket.recv_from(&mut self.recv_buffer)).await {
                Ok(Ok((len, addr))) => {
                    // Check rate limit before processing
                    if !self.check_rate_limit(&addr.ip()) {
                        trace!("Rate limited packet from {} during channel wait, dropping", addr);
                        continue;
                    }
                    let data = self.recv_buffer[..len].to_vec();
                    let _ = self.process_packet(&data, addr).await;
                }
                _ => continue,
            }
        }
    }

    /// Performs maintenance tasks (cleanup, keepalive).
    pub fn maintenance(&mut self) {
        let mut to_remove = Vec::new();

        for (peer_id, peer) in self.peers.iter_mut() {
            // Cleanup timed out queries
            peer.cleanup_timeouts();

            // Check for idle peers
            if peer.idle_time() > MAX_IDLE_TIME {
                peer.disconnect();
                to_remove.push(*peer_id);
            }
        }

        // Remove disconnected peers
        for peer_id in to_remove {
            self.remove_peer(&peer_id);
        }
    }

    /// Sends a response to a query.
    pub async fn send_answer(
        &mut self,
        peer_id: &[u8; 32],
        query_id: [u8; 32],
        answer: Vec<u8>,
    ) -> Result<()> {
        let (packet, has_channel) = {
            let peer = self.peers.get_mut(peer_id).ok_or_else(|| {
                AdnlError::InvalidPacket("peer not found".into())
            })?;

            let message = AdnlMessage::Answer { query_id, answer };
            let has_channel = peer.has_channel();
            let packet = peer.create_packet(message, !has_channel, &self.keypair.public_key);
            (packet, has_channel)
        };

        if has_channel {
            self.send_channel_packet(peer_id, &packet).await
        } else {
            self.send_initial_packet(peer_id, &packet).await
        }
    }
}

/// Generates a random query ID.
fn generate_query_id() -> [u8; 32] {
    use rand::RngCore;
    let mut id = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut id);
    id
}

/// Hex encoding helper (for debugging).
mod hex {
    pub fn encode(data: &[u8]) -> String {
        data.iter().map(|b| format!("{:02x}", b)).collect()
    }
}

impl std::fmt::Debug for AdnlNode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AdnlNode")
            .field("key_id", &hex::encode(&self.key_id[..8]))
            .field("local_addr", &self.socket.local_addr().ok())
            .field("peers", &self.peers.len())
            .field("timeout", &self.timeout)
            .field("rate_limit_config", &self.rate_limit_config)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_node_creation() {
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let node = AdnlNode::bind(addr).await.unwrap();

        assert_eq!(node.public_key().len(), 32);
        assert_eq!(node.key_id().len(), 32);
    }

    #[tokio::test]
    async fn test_add_peer() {
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let mut node = AdnlNode::bind(addr).await.unwrap();

        let peer_keypair = Ed25519Keypair::generate();
        let peer_addr: SocketAddr = "127.0.0.1:30303".parse().unwrap();

        node.add_peer(peer_addr, &peer_keypair.public_key).await.unwrap();

        let peer_id = node.get_peer_id(&peer_keypair.public_key);
        assert!(node.peer(&peer_id).is_some());
    }

    #[tokio::test]
    async fn test_remove_peer() {
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let mut node = AdnlNode::bind(addr).await.unwrap();

        let peer_keypair = Ed25519Keypair::generate();
        let peer_addr: SocketAddr = "127.0.0.1:30303".parse().unwrap();
        let peer_id = node.get_peer_id(&peer_keypair.public_key);

        node.add_peer(peer_addr, &peer_keypair.public_key).await.unwrap();
        assert!(node.peer(&peer_id).is_some());

        node.remove_peer(&peer_id);
        assert!(node.peer(&peer_id).is_none());
    }

    #[tokio::test]
    async fn test_peer_ids() {
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let mut node = AdnlNode::bind(addr).await.unwrap();

        let peer1 = Ed25519Keypair::generate();
        let peer2 = Ed25519Keypair::generate();

        node.add_peer("127.0.0.1:30303".parse().unwrap(), &peer1.public_key).await.unwrap();
        node.add_peer("127.0.0.1:30304".parse().unwrap(), &peer2.public_key).await.unwrap();

        let ids = node.peer_ids();
        assert_eq!(ids.len(), 2);
    }

    #[tokio::test]
    async fn test_rate_limit_config_default() {
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let node = AdnlNode::bind(addr).await.unwrap();

        let config = node.rate_limit_config();
        assert!(config.enabled);
        assert_eq!(config.packets_per_second, 100);
    }

    #[tokio::test]
    async fn test_rate_limit_config_custom() {
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let socket = UdpSocket::bind(addr).await.unwrap();
        let keypair = Ed25519Keypair::generate();
        let config = RateLimitConfig::new(50);

        let node = AdnlNode::with_keypair_and_config(socket, keypair, config).unwrap();

        let config = node.rate_limit_config();
        assert!(config.enabled);
        assert_eq!(config.packets_per_second, 50);
    }

    #[tokio::test]
    async fn test_rate_limit_disabled() {
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let socket = UdpSocket::bind(addr).await.unwrap();
        let keypair = Ed25519Keypair::generate();
        let config = RateLimitConfig::disabled();

        let node = AdnlNode::with_keypair_and_config(socket, keypair, config).unwrap();

        let config = node.rate_limit_config();
        assert!(!config.enabled);

        // When disabled, check_rate_limit should always return true
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        assert!(node.check_rate_limit(&ip));
    }

    #[tokio::test]
    async fn test_check_rate_limit_allows_within_limit() {
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let socket = UdpSocket::bind(addr).await.unwrap();
        let keypair = Ed25519Keypair::generate();
        let config = RateLimitConfig::new(100);

        let node = AdnlNode::with_keypair_and_config(socket, keypair, config).unwrap();

        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        // First check should always pass
        assert!(node.check_rate_limit(&ip));
    }

    #[tokio::test]
    async fn test_set_rate_limit_config() {
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let mut node = AdnlNode::bind(addr).await.unwrap();

        // Initially enabled with default
        assert!(node.rate_limit_config().enabled);

        // Disable rate limiting
        node.set_rate_limit_config(RateLimitConfig::disabled());
        assert!(!node.rate_limit_config().enabled);

        // Re-enable with custom limit
        node.set_rate_limit_config(RateLimitConfig::new(200));
        assert!(node.rate_limit_config().enabled);
        assert_eq!(node.rate_limit_config().packets_per_second, 200);
    }
}
