//! ADNL UDP peer management.
//!
//! A peer represents a remote node that we communicate with over UDP.
//! Each peer has its own state, including channel status and sequence numbers.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use ton_crypto::keys::calculate_key_id;

use crate::error::{AdnlError, Result};

use super::channel::AdnlChannel;
use super::packet::AdnlPacketContents;
use super::AdnlMessage;

/// Timeout for pending queries (30 seconds).
const QUERY_TIMEOUT: Duration = Duration::from_secs(30);

/// Timeout for channel establishment (10 seconds).
const CHANNEL_TIMEOUT: Duration = Duration::from_secs(10);

/// Maximum number of pending queries per peer.
const MAX_PENDING_QUERIES: usize = 100;

/// State of a peer connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerState {
    /// Initial state, no communication yet.
    New,
    /// Channel creation in progress.
    Connecting,
    /// Channel established, ready for communication.
    Connected,
    /// Peer is unreachable or has timed out.
    Disconnected,
}

/// A pending query waiting for a response.
struct PendingQuery {
    /// When the query was sent.
    sent_at: Instant,
    /// The query data (for potential retransmission).
    #[allow(dead_code)]
    data: Vec<u8>,
    /// Response channel (if using async completion).
    response_tx: Option<tokio::sync::oneshot::Sender<Vec<u8>>>,
}

/// Represents a remote peer for UDP ADNL communication.
pub struct AdnlPeer {
    /// The peer's socket address.
    addr: SocketAddr,
    /// The peer's public key.
    peer_pubkey: [u8; 32],
    /// The peer's key ID (derived from public key).
    peer_key_id: [u8; 32],
    /// The encrypted channel (if established).
    channel: Option<AdnlChannel>,
    /// Current connection state.
    state: PeerState,
    /// Outgoing sequence number.
    send_seqno: i64,
    /// Last received sequence number.
    recv_seqno: i64,
    /// Last confirmed sequence number.
    confirm_seqno: i64,
    /// Pending queries waiting for responses.
    pending_queries: HashMap<[u8; 32], PendingQuery>,
    /// Last activity timestamp.
    last_activity: Instant,
    /// Time when channel creation was initiated.
    channel_init_time: Option<Instant>,
    /// Our reinit date (for reconnection handling).
    reinit_date: i32,
    /// Peer's reinit date.
    peer_reinit_date: i32,
    /// Reassembly buffer for fragmented messages.
    fragment_buffer: HashMap<[u8; 32], FragmentBuffer>,
}

/// Buffer for reassembling fragmented messages.
struct FragmentBuffer {
    /// Expected total size.
    total_size: usize,
    /// Received fragments.
    fragments: Vec<(i32, Vec<u8>)>,
    /// When the first fragment was received.
    started_at: Instant,
}

impl AdnlPeer {
    /// Creates a new peer.
    pub fn new(addr: SocketAddr, peer_pubkey: &[u8; 32]) -> Self {
        let peer_key_id = calculate_key_id(peer_pubkey);
        let reinit_date = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i32)
            .unwrap_or(0);

        Self {
            addr,
            peer_pubkey: *peer_pubkey,
            peer_key_id,
            channel: None,
            state: PeerState::New,
            send_seqno: 0,
            recv_seqno: 0,
            confirm_seqno: 0,
            pending_queries: HashMap::new(),
            last_activity: Instant::now(),
            channel_init_time: None,
            reinit_date,
            peer_reinit_date: 0,
            fragment_buffer: HashMap::new(),
        }
    }

    /// Returns the peer's socket address.
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Returns the peer's public key.
    pub fn peer_pubkey(&self) -> &[u8; 32] {
        &self.peer_pubkey
    }

    /// Returns the peer's key ID.
    pub fn peer_key_id(&self) -> &[u8; 32] {
        &self.peer_key_id
    }

    /// Returns the current connection state.
    pub fn state(&self) -> PeerState {
        self.state
    }

    /// Returns true if the peer has an established channel.
    pub fn has_channel(&self) -> bool {
        self.channel.as_ref().is_some_and(|c| c.is_established())
    }

    /// Returns the channel if established.
    pub fn channel(&self) -> Option<&AdnlChannel> {
        self.channel.as_ref()
    }

    /// Returns a mutable reference to the channel.
    pub fn channel_mut(&mut self) -> Option<&mut AdnlChannel> {
        self.channel.as_mut()
    }

    /// Returns the next sequence number for sending.
    pub fn next_seqno(&mut self) -> i64 {
        self.send_seqno += 1;
        self.send_seqno
    }

    /// Returns the last received sequence number.
    pub fn recv_seqno(&self) -> i64 {
        self.recv_seqno
    }

    /// Returns the last confirmed sequence number.
    pub fn confirm_seqno(&self) -> i64 {
        self.confirm_seqno
    }

    /// Returns our reinit date.
    pub fn reinit_date(&self) -> i32 {
        self.reinit_date
    }

    /// Updates the last activity timestamp.
    pub fn touch(&mut self) {
        self.last_activity = Instant::now();
    }

    /// Returns the time since last activity.
    pub fn idle_time(&self) -> Duration {
        self.last_activity.elapsed()
    }

    /// Initiates channel creation.
    ///
    /// Returns the createChannel message to send.
    pub fn initiate_channel(&mut self) -> AdnlMessage {
        let (channel, pubkey, date) = AdnlChannel::new_pending();
        self.channel = Some(channel);
        self.state = PeerState::Connecting;
        self.channel_init_time = Some(Instant::now());

        AdnlMessage::CreateChannel { key: pubkey, date }
    }

    /// Handles a received createChannel message.
    ///
    /// Returns the confirmChannel message to send.
    pub fn handle_create_channel(&mut self, key: &[u8; 32], date: i32) -> AdnlMessage {
        let (channel, our_pubkey, our_date) = AdnlChannel::from_create_channel(key, date);
        self.channel = Some(channel);
        self.state = PeerState::Connected;
        self.touch();

        AdnlMessage::ConfirmChannel {
            key: our_pubkey,
            peer_key: *key,
            date: our_date,
        }
    }

    /// Handles a received confirmChannel message.
    pub fn handle_confirm_channel(&mut self, key: &[u8; 32], peer_key: &[u8; 32], date: i32) -> Result<()> {
        let channel = self.channel.as_mut().ok_or_else(|| {
            AdnlError::InvalidPacket("received confirmChannel without pending channel".into())
        })?;

        // Verify that peer_key matches our public key
        if peer_key != channel.our_public_key() {
            return Err(AdnlError::InvalidPacket("peer_key mismatch in confirmChannel".into()));
        }

        channel.confirm(key, date);
        self.state = PeerState::Connected;
        self.touch();

        Ok(())
    }

    /// Creates a query message.
    pub fn create_query(&mut self, query_id: [u8; 32], data: Vec<u8>) -> Result<AdnlMessage> {
        if self.pending_queries.len() >= MAX_PENDING_QUERIES {
            return Err(AdnlError::InvalidPacket("too many pending queries".into()));
        }

        self.pending_queries.insert(
            query_id,
            PendingQuery {
                sent_at: Instant::now(),
                data: data.clone(),
                response_tx: None,
            },
        );

        Ok(AdnlMessage::Query {
            query_id,
            query: data,
        })
    }

    /// Creates a query message with a response channel.
    pub fn create_query_with_response(
        &mut self,
        query_id: [u8; 32],
        data: Vec<u8>,
        response_tx: tokio::sync::oneshot::Sender<Vec<u8>>,
    ) -> Result<AdnlMessage> {
        if self.pending_queries.len() >= MAX_PENDING_QUERIES {
            return Err(AdnlError::InvalidPacket("too many pending queries".into()));
        }

        self.pending_queries.insert(
            query_id,
            PendingQuery {
                sent_at: Instant::now(),
                data: data.clone(),
                response_tx: Some(response_tx),
            },
        );

        Ok(AdnlMessage::Query {
            query_id,
            query: data,
        })
    }

    /// Handles a received answer message.
    ///
    /// Returns true if the answer was expected.
    pub fn handle_answer(&mut self, query_id: &[u8; 32], answer: Vec<u8>) -> bool {
        if let Some(pending) = self.pending_queries.remove(query_id) {
            if let Some(tx) = pending.response_tx {
                let _ = tx.send(answer);
            }
            self.touch();
            true
        } else {
            false
        }
    }

    /// Handles a received message part (for fragmentation).
    ///
    /// Returns the complete message if all parts have been received.
    pub fn handle_part(
        &mut self,
        hash: &[u8; 32],
        total_size: i32,
        offset: i32,
        data: Vec<u8>,
    ) -> Option<Vec<u8>> {
        let buffer = self.fragment_buffer.entry(*hash).or_insert_with(|| {
            FragmentBuffer {
                total_size: total_size as usize,
                fragments: Vec::new(),
                started_at: Instant::now(),
            }
        });

        buffer.fragments.push((offset, data));

        // Check if we have all parts
        let received_size: usize = buffer.fragments.iter().map(|(_, d)| d.len()).sum();
        if received_size >= buffer.total_size {
            // Sort by offset and concatenate
            buffer.fragments.sort_by_key(|(offset, _)| *offset);

            let mut complete = Vec::with_capacity(buffer.total_size);
            for (_, data) in &buffer.fragments {
                complete.extend_from_slice(data);
            }

            // Verify hash
            let computed_hash = ton_crypto::sha256::sha256(&complete);
            if computed_hash == *hash {
                self.fragment_buffer.remove(hash);
                self.touch();
                return Some(complete);
            }
        }

        None
    }

    /// Updates the received sequence number.
    pub fn update_recv_seqno(&mut self, seqno: i64) {
        if seqno > self.recv_seqno {
            self.recv_seqno = seqno;
        }
    }

    /// Updates the confirmed sequence number.
    pub fn update_confirm_seqno(&mut self, seqno: i64) {
        if seqno > self.confirm_seqno {
            self.confirm_seqno = seqno;
        }
    }

    /// Updates the peer's reinit date.
    pub fn update_peer_reinit_date(&mut self, date: i32) {
        if date > self.peer_reinit_date {
            self.peer_reinit_date = date;
        }
    }

    /// Cleans up timed out queries.
    ///
    /// Returns the number of queries that were cleaned up.
    pub fn cleanup_timeouts(&mut self) -> usize {
        let now = Instant::now();
        let before = self.pending_queries.len();

        self.pending_queries.retain(|_, q| {
            now.duration_since(q.sent_at) < QUERY_TIMEOUT
        });

        // Clean up old fragment buffers
        self.fragment_buffer.retain(|_, b| {
            now.duration_since(b.started_at) < QUERY_TIMEOUT
        });

        // Check for channel timeout
        if self.state == PeerState::Connecting
            && let Some(init_time) = self.channel_init_time
            && now.duration_since(init_time) > CHANNEL_TIMEOUT
        {
            self.state = PeerState::Disconnected;
            self.channel = None;
        }

        before - self.pending_queries.len()
    }

    /// Creates a packet contents structure for sending.
    ///
    /// This handles adding sequence numbers and other metadata.
    pub fn create_packet(&mut self, message: AdnlMessage, include_from: bool, our_pubkey: &[u8; 32]) -> AdnlPacketContents {
        let mut packet = AdnlPacketContents::with_message(message);

        // Add sender info for initial packets
        if include_from {
            packet.set_from(*our_pubkey);
        }

        // Add sequence numbers
        packet.set_seqno(self.next_seqno());

        if self.recv_seqno > 0 {
            packet.set_confirm_seqno(self.recv_seqno);
        }

        // Add reinit date for robustness
        if self.reinit_date > 0 {
            packet.set_reinit_date(self.reinit_date);
        }

        packet
    }

    /// Processes a received packet.
    pub fn process_packet(&mut self, packet: &AdnlPacketContents) {
        // Update sequence numbers
        if let Some(seqno) = packet.seqno {
            self.update_recv_seqno(seqno);
        }
        if let Some(confirm) = packet.confirm_seqno {
            self.update_confirm_seqno(confirm);
        }
        if let Some(date) = packet.reinit_date {
            self.update_peer_reinit_date(date);
        }

        self.touch();
    }

    /// Marks the peer as disconnected.
    pub fn disconnect(&mut self) {
        self.state = PeerState::Disconnected;
        if let Some(ref mut channel) = self.channel {
            channel.close();
        }
    }

    /// Resets the peer for reconnection.
    pub fn reset(&mut self) {
        self.channel = None;
        self.state = PeerState::New;
        self.send_seqno = 0;
        self.recv_seqno = 0;
        self.confirm_seqno = 0;
        self.pending_queries.clear();
        self.fragment_buffer.clear();
        self.reinit_date = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i32)
            .unwrap_or(0);
        self.peer_reinit_date = 0;
        self.touch();
    }
}

impl std::fmt::Debug for AdnlPeer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AdnlPeer")
            .field("addr", &self.addr)
            .field("state", &self.state)
            .field("has_channel", &self.has_channel())
            .field("send_seqno", &self.send_seqno)
            .field("recv_seqno", &self.recv_seqno)
            .field("pending_queries", &self.pending_queries.len())
            .field("idle_time", &self.idle_time())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ton_crypto::x25519::X25519Keypair;

    #[test]
    fn test_peer_creation() {
        let keypair = X25519Keypair::generate();
        let addr: SocketAddr = "127.0.0.1:30303".parse().unwrap();

        let peer = AdnlPeer::new(addr, &keypair.public_key);

        assert_eq!(peer.addr(), addr);
        assert_eq!(peer.peer_pubkey(), &keypair.public_key);
        assert_eq!(peer.state(), PeerState::New);
        assert!(!peer.has_channel());
    }

    #[test]
    fn test_channel_initiation() {
        let keypair = X25519Keypair::generate();
        let addr: SocketAddr = "127.0.0.1:30303".parse().unwrap();

        let mut peer = AdnlPeer::new(addr, &keypair.public_key);
        let msg = peer.initiate_channel();

        assert_eq!(peer.state(), PeerState::Connecting);

        if let AdnlMessage::CreateChannel { key, date } = msg {
            assert_eq!(key.len(), 32);
            assert!(date > 0);
        } else {
            panic!("Expected CreateChannel message");
        }
    }

    #[test]
    fn test_sequence_numbers() {
        let keypair = X25519Keypair::generate();
        let addr: SocketAddr = "127.0.0.1:30303".parse().unwrap();

        let mut peer = AdnlPeer::new(addr, &keypair.public_key);

        assert_eq!(peer.next_seqno(), 1);
        assert_eq!(peer.next_seqno(), 2);
        assert_eq!(peer.next_seqno(), 3);
    }

    #[test]
    fn test_query_management() {
        let keypair = X25519Keypair::generate();
        let addr: SocketAddr = "127.0.0.1:30303".parse().unwrap();

        let mut peer = AdnlPeer::new(addr, &keypair.public_key);

        let query_id = [1u8; 32];
        let data = b"test query".to_vec();

        let msg = peer.create_query(query_id, data.clone()).unwrap();

        if let AdnlMessage::Query { query_id: qid, query } = msg {
            assert_eq!(qid, query_id);
            assert_eq!(query, data);
        } else {
            panic!("Expected Query message");
        }

        // Answer the query
        let answer = b"test answer".to_vec();
        assert!(peer.handle_answer(&query_id, answer));

        // Answering again should return false
        assert!(!peer.handle_answer(&query_id, b"duplicate".to_vec()));
    }

    #[test]
    fn test_peer_reset() {
        let keypair = X25519Keypair::generate();
        let addr: SocketAddr = "127.0.0.1:30303".parse().unwrap();

        let mut peer = AdnlPeer::new(addr, &keypair.public_key);
        peer.next_seqno();
        peer.next_seqno();
        peer.initiate_channel();

        peer.reset();

        assert_eq!(peer.state(), PeerState::New);
        assert!(!peer.has_channel());
        assert_eq!(peer.next_seqno(), 1); // Reset to 0, first call returns 1
    }
}
