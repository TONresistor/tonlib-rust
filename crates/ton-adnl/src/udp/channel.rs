//! ADNL UDP channel management.
//!
//! Channels provide efficient encrypted communication between peers.
//! Once established, channel encryption uses symmetric keys derived from
//! an ECDH exchange, avoiding the overhead of public key operations.

use ton_crypto::{
    aes_ctr::AesCtrCipher,
    keys::calculate_key_id,
    sha256::sha256,
    x25519::X25519Keypair,
};

/// State of a channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelState {
    /// Channel creation has been initiated, waiting for confirmation.
    Pending,
    /// Channel is fully established and ready for use.
    Established,
    /// Channel has been closed or failed.
    Closed,
}

/// An encrypted ADNL channel between two peers.
///
/// Channels use symmetric encryption after the initial ECDH key exchange.
/// This is more efficient than encrypting each packet with public key crypto.
///
/// Each channel has two IDs:
/// - `in_channel_id`: ID for incoming packets (hash of our decryption key)
/// - `out_channel_id`: ID for outgoing packets (hash of our encryption key)
///
/// Note: Our `out_channel_id` equals the peer's `in_channel_id`, and vice versa.
#[derive(Clone)]
pub struct AdnlChannel {
    /// Channel ID for incoming packets (hash of decryption key).
    /// The peer uses this ID when sending packets to us.
    in_channel_id: [u8; 32],
    /// Channel ID for outgoing packets (hash of encryption key).
    /// We prefix outgoing packets with this ID.
    out_channel_id: [u8; 32],
    /// Cipher for encrypting outgoing packets.
    send_cipher: AesCtrCipher,
    /// Cipher for decrypting incoming packets.
    recv_cipher: AesCtrCipher,
    /// Our channel keypair.
    our_keypair: X25519Keypair,
    /// Peer's channel public key.
    peer_public_key: [u8; 32],
    /// Channel state.
    state: ChannelState,
    /// Creation timestamp.
    created_at: i32,
}

impl AdnlChannel {
    /// Creates a new channel in pending state.
    ///
    /// Call this when initiating a channel. The channel will be fully
    /// established once `confirm` is called with the peer's response.
    pub fn new_pending() -> (Self, [u8; 32], i32) {
        let keypair = X25519Keypair::generate();
        let public_key = keypair.public_key;
        let date = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i32)
            .unwrap_or(0);

        // Temporary ciphers - will be replaced when channel is confirmed
        let dummy_key = [0u8; 32];
        let dummy_iv = [0u8; 16];

        let channel = Self {
            in_channel_id: [0u8; 32],
            out_channel_id: [0u8; 32],
            send_cipher: AesCtrCipher::new(dummy_key, dummy_iv),
            recv_cipher: AesCtrCipher::new(dummy_key, dummy_iv),
            our_keypair: keypair,
            peer_public_key: [0u8; 32],
            state: ChannelState::Pending,
            created_at: date,
        };

        (channel, public_key, date)
    }

    /// Creates a channel from a received createChannel message.
    ///
    /// This is called by the receiver of a channel creation request.
    /// Returns the channel and the data needed for the confirmChannel response.
    pub fn from_create_channel(
        peer_public_key: &[u8; 32],
        peer_date: i32,
    ) -> (Self, [u8; 32], i32) {
        let keypair = X25519Keypair::generate();
        let our_public_key = keypair.public_key;
        let date = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i32)
            .unwrap_or(0);

        // Calculate shared secret
        let shared_secret = keypair.ecdh(peer_public_key);

        // Calculate key IDs
        let our_key_id = calculate_key_id(&our_public_key);
        let peer_key_id = calculate_key_id(peer_public_key);

        // Derive channel keys
        let (send_cipher, recv_cipher, in_channel_id, out_channel_id) =
            derive_channel_keys(&shared_secret, &our_key_id, &peer_key_id);

        let channel = Self {
            in_channel_id,
            out_channel_id,
            send_cipher,
            recv_cipher,
            our_keypair: keypair,
            peer_public_key: *peer_public_key,
            state: ChannelState::Established,
            created_at: peer_date.max(date),
        };

        (channel, our_public_key, date)
    }

    /// Confirms a pending channel with the peer's response.
    ///
    /// Called when receiving a confirmChannel message for a channel we initiated.
    pub fn confirm(&mut self, peer_public_key: &[u8; 32], _peer_date: i32) {
        // Calculate shared secret
        let shared_secret = self.our_keypair.ecdh(peer_public_key);

        // Calculate key IDs
        let our_key_id = calculate_key_id(&self.our_keypair.public_key);
        let peer_key_id = calculate_key_id(peer_public_key);

        // Derive channel keys
        let (send_cipher, recv_cipher, in_channel_id, out_channel_id) =
            derive_channel_keys(&shared_secret, &our_key_id, &peer_key_id);

        self.in_channel_id = in_channel_id;
        self.out_channel_id = out_channel_id;
        self.send_cipher = send_cipher;
        self.recv_cipher = recv_cipher;
        self.peer_public_key = *peer_public_key;
        self.state = ChannelState::Established;
    }

    /// Returns the incoming channel ID (used to identify packets from peer).
    pub fn in_channel_id(&self) -> &[u8; 32] {
        &self.in_channel_id
    }

    /// Returns the outgoing channel ID (used as prefix on packets to peer).
    pub fn out_channel_id(&self) -> &[u8; 32] {
        &self.out_channel_id
    }

    /// Returns the channel ID for backward compatibility.
    /// This returns the incoming channel ID.
    #[deprecated(note = "Use in_channel_id() or out_channel_id() instead")]
    pub fn channel_id(&self) -> &[u8; 32] {
        &self.in_channel_id
    }

    /// Returns the channel state.
    pub fn state(&self) -> ChannelState {
        self.state
    }

    /// Returns true if the channel is established and ready for use.
    pub fn is_established(&self) -> bool {
        self.state == ChannelState::Established
    }

    /// Returns our public key for this channel.
    pub fn our_public_key(&self) -> &[u8; 32] {
        &self.our_keypair.public_key
    }

    /// Returns the peer's public key for this channel.
    pub fn peer_public_key(&self) -> &[u8; 32] {
        &self.peer_public_key
    }

    /// Returns the creation timestamp.
    pub fn created_at(&self) -> i32 {
        self.created_at
    }

    /// Encrypts data for sending through this channel.
    pub fn encrypt(&mut self, data: &[u8]) -> Vec<u8> {
        self.send_cipher.encrypt(data)
    }

    /// Decrypts data received through this channel.
    pub fn decrypt(&mut self, data: &[u8]) -> Vec<u8> {
        self.recv_cipher.decrypt(data)
    }

    /// Encrypts data in place.
    pub fn encrypt_in_place(&mut self, data: &mut [u8]) {
        self.send_cipher.encrypt_in_place(data);
    }

    /// Decrypts data in place.
    pub fn decrypt_in_place(&mut self, data: &mut [u8]) {
        self.recv_cipher.decrypt_in_place(data);
    }

    /// Closes the channel.
    pub fn close(&mut self) {
        self.state = ChannelState::Closed;
    }

    /// Resets the ciphers to their initial state.
    ///
    /// This should be called at the start of each packet encryption/decryption
    /// since ADNL UDP packets are independent.
    pub fn reset_ciphers(&mut self) {
        self.send_cipher.reset();
        self.recv_cipher.reset();
    }
}

/// Derives channel encryption keys from the shared secret and key IDs.
///
/// The key derivation follows the official TON ADNL specification:
/// - Two keys are derived: shared_secret and reversed(shared_secret)
/// - Keys are assigned based on comparing peer IDs (SHA256 of TL-serialized Ed25519 pubkeys)
/// - The party with the smaller ID uses shared_secret for decryption, reversed for encryption
/// - Each party has two channel IDs:
///   - in_channel_id: SHA256(TL_PREFIX_AES || decryption_key) - identifies incoming packets
///   - out_channel_id: SHA256(TL_PREFIX_AES || encryption_key) - prefixed on outgoing packets
///
/// Reference: ton-blockchain/ton/adnl/adnl-channel.cpp, tonutils-go/adnl/channel.go
fn derive_channel_keys(
    shared_secret: &[u8; 32],
    our_key_id: &[u8; 32],
    peer_key_id: &[u8; 32],
) -> (AesCtrCipher, AesCtrCipher, [u8; 32], [u8; 32]) {
    // Create the two channel keys: original and reversed shared secret
    let key_original = *shared_secret;
    let mut key_reversed = *shared_secret;
    key_reversed.reverse();

    // Determine key assignment based on peer ID comparison
    // Compare as big integers (tonutils-go uses big.Int.Cmp)
    // If peer_key_id < our_key_id: swap keys
    //
    // Initial: decKey = shared_secret, encKey = reversed
    // If theirID < ourID: swap -> decKey = reversed, encKey = shared_secret
    let (recv_key, send_key) = if peer_key_id < our_key_id {
        // Peer ID is smaller, swap keys
        (key_reversed, key_original)
    } else {
        // Our ID is smaller (or equal), keep original assignment
        (key_original, key_reversed)
    };

    // Calculate channel IDs as SHA256(TL_PREFIX_AES || key)
    // - in_channel_id uses decryption key (identifies incoming packets)
    // - out_channel_id uses encryption key (prefixed on outgoing packets)
    // Reference: tonutils-go/adnl/channel.go
    use ton_crypto::keys::calculate_aes_key_id;
    let in_channel_id = calculate_aes_key_id(&recv_key);
    let out_channel_id = calculate_aes_key_id(&send_key);

    // Derive IVs from keys
    let send_iv = derive_iv_from_key(&send_key);
    let recv_iv = derive_iv_from_key(&recv_key);

    let send_cipher = AesCtrCipher::new(send_key, send_iv);
    let recv_cipher = AesCtrCipher::new(recv_key, recv_iv);

    (send_cipher, recv_cipher, in_channel_id, out_channel_id)
}

/// Derives an IV from a key by hashing it.
fn derive_iv_from_key(key: &[u8; 32]) -> [u8; 16] {
    let hash = sha256(key);
    let mut iv = [0u8; 16];
    iv.copy_from_slice(&hash[..16]);
    iv
}

/// Derives an IV from two key IDs.
#[allow(dead_code)]
fn derive_iv(key_id_a: &[u8; 32], key_id_b: &[u8; 32]) -> [u8; 16] {
    let mut iv_input = [0u8; 64];
    iv_input[..32].copy_from_slice(key_id_a);
    iv_input[32..].copy_from_slice(key_id_b);
    let hash = sha256(&iv_input);
    let mut iv = [0u8; 16];
    iv.copy_from_slice(&hash[..16]);
    iv
}

/// Calculate the channel key ID used as packet prefix.
///
/// This is the hash of the channel's shared secret, used to identify
/// which channel a packet belongs to.
#[allow(dead_code)]
pub fn calculate_channel_key_id(shared_secret: &[u8; 32]) -> [u8; 32] {
    // Use the AES key prefix for channel key IDs
    use ton_crypto::keys::calculate_aes_key_id;
    calculate_aes_key_id(shared_secret)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_channel_creation_pending() {
        let (channel, pubkey, date) = AdnlChannel::new_pending();

        assert_eq!(channel.state(), ChannelState::Pending);
        assert_eq!(pubkey.len(), 32);
        assert!(date > 0);
    }

    #[test]
    fn test_channel_from_create() {
        let peer_keypair = X25519Keypair::generate();
        let peer_date = 12345;

        let (channel, our_pubkey, _date) = AdnlChannel::from_create_channel(
            &peer_keypair.public_key,
            peer_date,
        );

        assert_eq!(channel.state(), ChannelState::Established);
        assert_eq!(our_pubkey.len(), 32);
        assert_eq!(channel.peer_public_key(), &peer_keypair.public_key);
    }

    #[test]
    fn test_channel_handshake() {
        // Simulate a full channel handshake between two parties

        // Alice initiates
        let (mut alice_channel, alice_pubkey, alice_date) = AdnlChannel::new_pending();

        // Bob receives createChannel and responds
        let (bob_channel, bob_pubkey, bob_date) = AdnlChannel::from_create_channel(
            &alice_pubkey,
            alice_date,
        );

        // Alice receives confirmChannel
        alice_channel.confirm(&bob_pubkey, bob_date);

        // Both channels should now be established
        assert!(alice_channel.is_established());
        assert!(bob_channel.is_established());

        // Verify cross-channel ID matching:
        // Alice's out_channel_id should match Bob's in_channel_id
        // Bob's out_channel_id should match Alice's in_channel_id
        assert_eq!(
            alice_channel.out_channel_id(),
            bob_channel.in_channel_id(),
            "Alice's outgoing ID should match Bob's incoming ID"
        );
        assert_eq!(
            bob_channel.out_channel_id(),
            alice_channel.in_channel_id(),
            "Bob's outgoing ID should match Alice's incoming ID"
        );
    }

    #[test]
    fn test_channel_encryption() {
        // Set up channels
        let (mut alice_channel, alice_pubkey, alice_date) = AdnlChannel::new_pending();
        let (mut bob_channel, bob_pubkey, bob_date) = AdnlChannel::from_create_channel(
            &alice_pubkey,
            alice_date,
        );
        alice_channel.confirm(&bob_pubkey, bob_date);

        // Alice sends to Bob
        let message = b"Hello, Bob!";
        let encrypted = alice_channel.encrypt(message);

        // Bob decrypts
        let decrypted = bob_channel.decrypt(&encrypted);

        assert_eq!(decrypted, message);

        // Reset ciphers for a new message
        alice_channel.reset_ciphers();
        bob_channel.reset_ciphers();

        // Bob sends to Alice
        let response = b"Hello, Alice!";
        let encrypted_response = bob_channel.encrypt(response);
        let decrypted_response = alice_channel.decrypt(&encrypted_response);

        assert_eq!(decrypted_response, response);
    }

    #[test]
    fn test_key_ordering() {
        // Test that key ordering is consistent regardless of who initiates

        let keypair_a = X25519Keypair::generate();
        let keypair_b = X25519Keypair::generate();

        let shared_ab = keypair_a.ecdh(&keypair_b.public_key);
        let shared_ba = keypair_b.ecdh(&keypair_a.public_key);

        // Shared secrets should be the same
        assert_eq!(shared_ab, shared_ba);

        let key_id_a = calculate_key_id(&keypair_a.public_key);
        let key_id_b = calculate_key_id(&keypair_b.public_key);

        let (send_a, recv_a, in_id_a, out_id_a) = derive_channel_keys(&shared_ab, &key_id_a, &key_id_b);
        let (send_b, recv_b, in_id_b, out_id_b) = derive_channel_keys(&shared_ba, &key_id_b, &key_id_a);

        // Cross-channel IDs should match:
        // A's out_channel_id should equal B's in_channel_id (A sends, B receives)
        // B's out_channel_id should equal A's in_channel_id (B sends, A receives)
        assert_eq!(out_id_a, in_id_b, "A's out should match B's in");
        assert_eq!(out_id_b, in_id_a, "B's out should match A's in");

        // A's send key should be B's receive key and vice versa
        assert_eq!(send_a.key(), recv_b.key());
        assert_eq!(recv_a.key(), send_b.key());
    }

    #[test]
    fn test_channel_close() {
        let (mut channel, _, _) = AdnlChannel::new_pending();

        channel.close();

        assert_eq!(channel.state(), ChannelState::Closed);
        assert!(!channel.is_established());
    }
}
