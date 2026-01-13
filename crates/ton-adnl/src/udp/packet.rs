//! ADNL UDP packet encoding and decoding.
//!
//! UDP packets have a different structure than TCP packets:
//!
//! ## Initial Packet (before channel):
//! ```text
//! +----------------+------------------+------------------+------------------+
//! | Server Key ID  | Client Pubkey    | SHA256(content)  | Encrypted Content|
//! | 32 bytes       | 32 bytes         | 32 bytes         | Variable         |
//! +----------------+------------------+------------------+------------------+
//! ```
//!
//! ## Channel Packet:
//! ```text
//! +----------------+------------------+------------------+
//! | Channel Key ID | SHA256(content)  | Encrypted Content|
//! | 32 bytes       | 32 bytes         | Variable         |
//! +----------------+------------------+------------------+
//! ```
//!
//! The content is `adnl.packetContents` which has a complex flag-based structure.

use rand::RngCore;

use ton_crypto::{
    aes_ctr::AesCtrCipher,
    keys::calculate_key_id,
    sha256::sha256,
    x25519::ecdh,
};

use crate::error::{AdnlError, Result};
use crate::tl::{TlReader, TlWriter};
use crate::tl::{
    ADNL_CREATE_CHANNEL, ADNL_CONFIRM_CHANNEL, ADNL_MESSAGE_QUERY,
    ADNL_MESSAGE_ANSWER, ADNL_MESSAGE_CUSTOM, ADNL_MESSAGE_PART, PUB_ED25519,
};

use super::AdnlMessage;

/// Maximum UDP packet size (64 KB minus headers).
pub const MAX_UDP_PACKET_SIZE: usize = 65507;

/// Minimum packet size (key_id + checksum).
pub const MIN_UDP_PACKET_SIZE: usize = 64;

/// Flags for AdnlPacketContents fields.
#[derive(Debug, Clone, Copy, Default)]
pub struct AdnlPacketFlags(u32);

impl AdnlPacketFlags {
    /// Flag: `from` field is present (sender's public key).
    pub const FROM: u32 = 0x1;
    /// Flag: `from_short` field is present (sender's key ID).
    pub const FROM_SHORT: u32 = 0x2;
    /// Flag: `message` field is present (single message).
    pub const MESSAGE: u32 = 0x4;
    /// Flag: `messages` field is present (multiple messages).
    pub const MESSAGES: u32 = 0x8;
    /// Flag: `address` field is present.
    pub const ADDRESS: u32 = 0x10;
    /// Flag: `priority_address` field is present.
    pub const PRIORITY_ADDRESS: u32 = 0x20;
    /// Flag: `seqno` field is present.
    pub const SEQNO: u32 = 0x40;
    /// Flag: `confirm_seqno` field is present.
    pub const CONFIRM_SEQNO: u32 = 0x80;
    /// Flag: `recv_addr_list_version` field is present.
    pub const RECV_ADDR_LIST_VERSION: u32 = 0x100;
    /// Flag: `recv_priority_addr_list_version` field is present.
    pub const RECV_PRIORITY_ADDR_LIST_VERSION: u32 = 0x200;
    /// Flag: `reinit_date` field is present.
    pub const REINIT_DATE: u32 = 0x400;
    /// Flag: `dst_reinit_date` field is present.
    pub const DST_REINIT_DATE: u32 = 0x800;
    /// Flag: `signature` field is present.
    pub const SIGNATURE: u32 = 0x1000;
    /// Flag: rand1 is 15 bytes (otherwise 7).
    pub const RAND1_15: u32 = 0x4000;
    /// Flag: rand2 is 15 bytes (otherwise 7).
    pub const RAND2_15: u32 = 0x8000;

    /// Creates new flags with the given value.
    pub fn new(flags: u32) -> Self {
        Self(flags)
    }

    /// Returns the raw flags value.
    pub fn value(&self) -> u32 {
        self.0
    }

    /// Checks if a flag is set.
    pub fn has(&self, flag: u32) -> bool {
        (self.0 & flag) != 0
    }

    /// Sets a flag.
    pub fn set(&mut self, flag: u32) {
        self.0 |= flag;
    }

    /// Clears a flag.
    pub fn clear(&mut self, flag: u32) {
        self.0 &= !flag;
    }

    /// Returns the size of rand1 (7 or 15 bytes).
    pub fn rand1_size(&self) -> usize {
        if self.has(Self::RAND1_15) { 15 } else { 7 }
    }

    /// Returns the size of rand2 (7 or 15 bytes).
    pub fn rand2_size(&self) -> usize {
        if self.has(Self::RAND2_15) { 15 } else { 7 }
    }
}

/// ADNL packet contents (adnl.packetContents).
///
/// This is the inner structure of UDP ADNL packets.
#[derive(Debug, Clone)]
pub struct AdnlPacketContents {
    /// Random padding at the start (7 or 15 bytes).
    pub rand1: Vec<u8>,
    /// Flags indicating which optional fields are present.
    pub flags: AdnlPacketFlags,
    /// Sender's public key (if FROM flag is set).
    pub from: Option<[u8; 32]>,
    /// Sender's key ID (if FROM_SHORT flag is set).
    pub from_short: Option<[u8; 32]>,
    /// Single message (if MESSAGE flag is set).
    pub message: Option<AdnlMessage>,
    /// Multiple messages (if MESSAGES flag is set).
    pub messages: Option<Vec<AdnlMessage>>,
    /// Address list (if ADDRESS flag is set).
    pub address: Option<Vec<u8>>,
    /// Priority address list (if PRIORITY_ADDRESS flag is set).
    pub priority_address: Option<Vec<u8>>,
    /// Sequence number (if SEQNO flag is set).
    pub seqno: Option<i64>,
    /// Confirmed sequence number (if CONFIRM_SEQNO flag is set).
    pub confirm_seqno: Option<i64>,
    /// Received address list version (if RECV_ADDR_LIST_VERSION flag is set).
    pub recv_addr_list_version: Option<i32>,
    /// Received priority address list version.
    pub recv_priority_addr_list_version: Option<i32>,
    /// Reinit date (if REINIT_DATE flag is set).
    pub reinit_date: Option<i32>,
    /// Destination reinit date (if DST_REINIT_DATE flag is set).
    pub dst_reinit_date: Option<i32>,
    /// Signature (if SIGNATURE flag is set).
    pub signature: Option<[u8; 64]>,
    /// Random padding at the end (7 or 15 bytes).
    pub rand2: Vec<u8>,
}

impl AdnlPacketContents {
    /// Creates a new packet with minimal fields.
    pub fn new() -> Self {
        let mut rand1 = vec![0u8; 7];
        let mut rand2 = vec![0u8; 7];
        rand::thread_rng().fill_bytes(&mut rand1);
        rand::thread_rng().fill_bytes(&mut rand2);

        // Clear bit 0x80 in first byte of rand1 to indicate 7-byte padding
        // (if bit is set, decoder expects 15 bytes)
        rand1[0] &= 0x7F;

        Self {
            rand1,
            flags: AdnlPacketFlags::default(),
            from: None,
            from_short: None,
            message: None,
            messages: None,
            address: None,
            priority_address: None,
            seqno: None,
            confirm_seqno: None,
            recv_addr_list_version: None,
            recv_priority_addr_list_version: None,
            reinit_date: None,
            dst_reinit_date: None,
            signature: None,
            rand2,
        }
    }

    /// Creates a packet with a single message.
    pub fn with_message(message: AdnlMessage) -> Self {
        let mut packet = Self::new();
        packet.message = Some(message);
        packet.flags.set(AdnlPacketFlags::MESSAGE);
        packet
    }

    /// Creates a packet with multiple messages.
    pub fn with_messages(messages: Vec<AdnlMessage>) -> Self {
        let mut packet = Self::new();
        packet.messages = Some(messages);
        packet.flags.set(AdnlPacketFlags::MESSAGES);
        packet
    }

    /// Sets the sender's public key.
    pub fn set_from(&mut self, pubkey: [u8; 32]) {
        self.from = Some(pubkey);
        self.flags.set(AdnlPacketFlags::FROM);
    }

    /// Sets the sender's key ID.
    pub fn set_from_short(&mut self, key_id: [u8; 32]) {
        self.from_short = Some(key_id);
        self.flags.set(AdnlPacketFlags::FROM_SHORT);
    }

    /// Sets the sequence number.
    pub fn set_seqno(&mut self, seqno: i64) {
        self.seqno = Some(seqno);
        self.flags.set(AdnlPacketFlags::SEQNO);
    }

    /// Sets the confirmed sequence number.
    pub fn set_confirm_seqno(&mut self, seqno: i64) {
        self.confirm_seqno = Some(seqno);
        self.flags.set(AdnlPacketFlags::CONFIRM_SEQNO);
    }

    /// Sets the reinit date.
    pub fn set_reinit_date(&mut self, date: i32) {
        self.reinit_date = Some(date);
        self.flags.set(AdnlPacketFlags::REINIT_DATE);
    }

    /// Encodes the packet contents to TL format.
    pub fn encode(&self) -> Vec<u8> {
        let mut writer = TlWriter::new();

        // rand1
        writer.write_raw(&self.rand1);

        // flags
        writer.write_u32(self.flags.value());

        // Optional fields based on flags
        if let Some(ref from) = self.from {
            // pub.ed25519 key:int256 = PublicKey
            writer.write_u32(PUB_ED25519);
            writer.write_int256(from);
        }

        if let Some(ref from_short) = self.from_short {
            // adnl.id.short id:int256 = adnl.id.Short
            writer.write_int256(from_short);
        }

        if let Some(ref message) = self.message {
            encode_message(&mut writer, message);
        }

        if let Some(ref messages) = self.messages {
            // Vector of messages
            writer.write_u32(messages.len() as u32);
            for msg in messages {
                encode_message(&mut writer, msg);
            }
        }

        // Address fields (simplified - just raw bytes if present)
        if let Some(ref address) = self.address {
            writer.write_bytes(address);
        }

        if let Some(ref priority_address) = self.priority_address {
            writer.write_bytes(priority_address);
        }

        if let Some(seqno) = self.seqno {
            writer.write_i64(seqno);
        }

        if let Some(confirm_seqno) = self.confirm_seqno {
            writer.write_i64(confirm_seqno);
        }

        if let Some(version) = self.recv_addr_list_version {
            writer.write_i32(version);
        }

        if let Some(version) = self.recv_priority_addr_list_version {
            writer.write_i32(version);
        }

        if let Some(date) = self.reinit_date {
            writer.write_i32(date);
        }

        if let Some(date) = self.dst_reinit_date {
            writer.write_i32(date);
        }

        if let Some(ref signature) = self.signature {
            writer.write_raw(signature);
        }

        // rand2
        writer.write_raw(&self.rand2);

        writer.finish()
    }

    /// Decodes packet contents from TL format.
    pub fn decode(data: &[u8]) -> Result<Self> {
        let mut reader = TlReader::new(data);

        // First byte determines rand1 size
        // If first byte has bit 0x80 set, rand1 is 15 bytes, otherwise 7 bytes
        let first_byte = if !data.is_empty() { data[0] } else { 0 };
        let rand1_size = if first_byte & 0x80 != 0 { 15 } else { 7 };
        let rand1 = reader.read_raw(rand1_size)?.to_vec();

        // flags
        let flags_value = reader.read_u32()?;
        let flags = AdnlPacketFlags::new(flags_value);

        let mut packet = Self {
            rand1,
            flags,
            from: None,
            from_short: None,
            message: None,
            messages: None,
            address: None,
            priority_address: None,
            seqno: None,
            confirm_seqno: None,
            recv_addr_list_version: None,
            recv_priority_addr_list_version: None,
            reinit_date: None,
            dst_reinit_date: None,
            signature: None,
            rand2: Vec::new(),
        };

        // from
        if flags.has(AdnlPacketFlags::FROM) {
            let type_id = reader.read_u32()?;
            if type_id != PUB_ED25519 {
                return Err(AdnlError::UnexpectedMessageType(type_id));
            }
            packet.from = Some(reader.read_int256()?);
        }

        // from_short
        if flags.has(AdnlPacketFlags::FROM_SHORT) {
            packet.from_short = Some(reader.read_int256()?);
        }

        // message
        if flags.has(AdnlPacketFlags::MESSAGE) {
            packet.message = Some(decode_message(&mut reader)?);
        }

        // messages
        if flags.has(AdnlPacketFlags::MESSAGES) {
            let count = reader.read_u32()? as usize;
            let mut messages = Vec::with_capacity(count);
            for _ in 0..count {
                messages.push(decode_message(&mut reader)?);
            }
            packet.messages = Some(messages);
        }

        // address
        if flags.has(AdnlPacketFlags::ADDRESS) {
            packet.address = Some(reader.read_bytes()?);
        }

        // priority_address
        if flags.has(AdnlPacketFlags::PRIORITY_ADDRESS) {
            packet.priority_address = Some(reader.read_bytes()?);
        }

        // seqno
        if flags.has(AdnlPacketFlags::SEQNO) {
            packet.seqno = Some(reader.read_i64()?);
        }

        // confirm_seqno
        if flags.has(AdnlPacketFlags::CONFIRM_SEQNO) {
            packet.confirm_seqno = Some(reader.read_i64()?);
        }

        // recv_addr_list_version
        if flags.has(AdnlPacketFlags::RECV_ADDR_LIST_VERSION) {
            packet.recv_addr_list_version = Some(reader.read_i32()?);
        }

        // recv_priority_addr_list_version
        if flags.has(AdnlPacketFlags::RECV_PRIORITY_ADDR_LIST_VERSION) {
            packet.recv_priority_addr_list_version = Some(reader.read_i32()?);
        }

        // reinit_date
        if flags.has(AdnlPacketFlags::REINIT_DATE) {
            packet.reinit_date = Some(reader.read_i32()?);
        }

        // dst_reinit_date
        if flags.has(AdnlPacketFlags::DST_REINIT_DATE) {
            packet.dst_reinit_date = Some(reader.read_i32()?);
        }

        // signature
        if flags.has(AdnlPacketFlags::SIGNATURE) {
            let sig_bytes = reader.read_raw(64)?;
            let mut signature = [0u8; 64];
            signature.copy_from_slice(sig_bytes);
            packet.signature = Some(signature);
        }

        // rand2 - remaining bytes
        let rand2_size = if flags.has(AdnlPacketFlags::RAND2_15) { 15 } else { 7 };
        if reader.remaining_len() >= rand2_size {
            packet.rand2 = reader.read_raw(rand2_size)?.to_vec();
        }

        Ok(packet)
    }
}

impl Default for AdnlPacketContents {
    fn default() -> Self {
        Self::new()
    }
}

/// Encodes an ADNL message to TL format.
fn encode_message(writer: &mut TlWriter, message: &AdnlMessage) {
    match message {
        AdnlMessage::CreateChannel { key, date } => {
            writer.write_u32(ADNL_CREATE_CHANNEL);
            writer.write_int256(key);
            writer.write_i32(*date);
        }
        AdnlMessage::ConfirmChannel { key, peer_key, date } => {
            writer.write_u32(ADNL_CONFIRM_CHANNEL);
            writer.write_int256(key);
            writer.write_int256(peer_key);
            writer.write_i32(*date);
        }
        AdnlMessage::Query { query_id, query } => {
            writer.write_u32(ADNL_MESSAGE_QUERY);
            writer.write_int256(query_id);
            writer.write_bytes(query);
        }
        AdnlMessage::Answer { query_id, answer } => {
            writer.write_u32(ADNL_MESSAGE_ANSWER);
            writer.write_int256(query_id);
            writer.write_bytes(answer);
        }
        AdnlMessage::Custom { data } => {
            writer.write_u32(ADNL_MESSAGE_CUSTOM);
            writer.write_bytes(data);
        }
        AdnlMessage::Part { hash, total_size, offset, data } => {
            writer.write_u32(ADNL_MESSAGE_PART);
            writer.write_int256(hash);
            writer.write_i32(*total_size);
            writer.write_i32(*offset);
            writer.write_bytes(data);
        }
    }
}

/// Decodes an ADNL message from TL format.
fn decode_message(reader: &mut TlReader) -> Result<AdnlMessage> {
    let type_id = reader.read_u32()?;

    match type_id {
        ADNL_CREATE_CHANNEL => {
            let key = reader.read_int256()?;
            let date = reader.read_i32()?;
            Ok(AdnlMessage::CreateChannel { key, date })
        }
        ADNL_CONFIRM_CHANNEL => {
            let key = reader.read_int256()?;
            let peer_key = reader.read_int256()?;
            let date = reader.read_i32()?;
            Ok(AdnlMessage::ConfirmChannel { key, peer_key, date })
        }
        ADNL_MESSAGE_QUERY => {
            let query_id = reader.read_int256()?;
            let query = reader.read_bytes()?;
            Ok(AdnlMessage::Query { query_id, query })
        }
        ADNL_MESSAGE_ANSWER => {
            let query_id = reader.read_int256()?;
            let answer = reader.read_bytes()?;
            Ok(AdnlMessage::Answer { query_id, answer })
        }
        ADNL_MESSAGE_CUSTOM => {
            let data = reader.read_bytes()?;
            Ok(AdnlMessage::Custom { data })
        }
        ADNL_MESSAGE_PART => {
            let hash = reader.read_int256()?;
            let total_size = reader.read_i32()?;
            let offset = reader.read_i32()?;
            let data = reader.read_bytes()?;
            Ok(AdnlMessage::Part { hash, total_size, offset, data })
        }
        _ => Err(AdnlError::UnexpectedMessageType(type_id)),
    }
}

/// A complete UDP packet (either initial or channel).
#[derive(Debug)]
pub enum UdpPacket {
    /// Initial packet (before channel is established).
    Initial {
        /// Recipient's key ID.
        recipient_key_id: [u8; 32],
        /// Sender's public key.
        sender_pubkey: [u8; 32],
        /// Content checksum.
        checksum: [u8; 32],
        /// Encrypted content.
        encrypted_content: Vec<u8>,
    },
    /// Channel packet (inside established channel).
    Channel {
        /// Channel key ID.
        channel_key_id: [u8; 32],
        /// Content checksum.
        checksum: [u8; 32],
        /// Encrypted content.
        encrypted_content: Vec<u8>,
    },
}

/// Encodes a UDP packet for sending.
///
/// # Arguments
///
/// * `content` - The packet content to encode.
/// * `recipient_pubkey` - The recipient's public key.
/// * `sender_privkey` - The sender's private key.
/// * `sender_pubkey` - The sender's public key.
///
/// # Returns
///
/// The encoded packet ready to send.
pub fn encode_udp_packet(
    content: &AdnlPacketContents,
    recipient_pubkey: &[u8; 32],
    sender_privkey: &[u8; 32],
    sender_pubkey: &[u8; 32],
) -> Vec<u8> {
    let encoded_content = content.encode();

    // Calculate recipient's key ID
    let recipient_key_id = calculate_key_id(recipient_pubkey);

    // Calculate checksum
    let checksum = sha256(&encoded_content);

    // Calculate shared secret
    let shared_secret = ecdh(sender_privkey, recipient_pubkey);

    // Derive encryption key and IV from shared secret and checksum
    let (key, iv) = derive_packet_key(&shared_secret, &checksum);

    // Encrypt content
    let mut cipher = AesCtrCipher::new(key, iv);
    let encrypted_content = cipher.encrypt(&encoded_content);

    // Build packet
    let mut packet = Vec::with_capacity(32 + 32 + 32 + encrypted_content.len());
    packet.extend_from_slice(&recipient_key_id);
    packet.extend_from_slice(sender_pubkey);
    packet.extend_from_slice(&checksum);
    packet.extend_from_slice(&encrypted_content);

    packet
}

/// Encodes a channel packet.
///
/// # Arguments
///
/// * `content` - The packet content to encode.
/// * `channel_key_id` - The channel key ID.
/// * `cipher` - The channel cipher.
///
/// # Returns
///
/// The encoded packet ready to send.
#[allow(dead_code)]
pub fn encode_channel_packet(
    content: &AdnlPacketContents,
    channel_key_id: &[u8; 32],
    cipher: &mut AesCtrCipher,
) -> Vec<u8> {
    let encoded_content = content.encode();

    // Calculate checksum
    let checksum = sha256(&encoded_content);

    // Encrypt content
    cipher.reset();
    let encrypted_content = cipher.encrypt(&encoded_content);

    // Build packet
    let mut packet = Vec::with_capacity(32 + 32 + encrypted_content.len());
    packet.extend_from_slice(channel_key_id);
    packet.extend_from_slice(&checksum);
    packet.extend_from_slice(&encrypted_content);

    packet
}

/// Decodes a UDP packet.
///
/// # Arguments
///
/// * `data` - The raw packet data.
/// * `our_key_id` - Our key ID (to identify initial packets to us).
/// * `our_privkey` - Our private key (for decryption).
/// * `channel_key_ids` - Known channel key IDs and their decrypt functions.
///
/// # Returns
///
/// The decoded packet and content.
pub fn decode_udp_packet(
    data: &[u8],
    our_key_id: &[u8; 32],
    our_privkey: &[u8; 32],
) -> Result<(UdpPacket, AdnlPacketContents)> {
    if data.len() < MIN_UDP_PACKET_SIZE {
        return Err(AdnlError::InvalidPacket("packet too short".into()));
    }

    // First 32 bytes are the key ID
    let key_id: [u8; 32] = data[..32].try_into().unwrap();

    // Check if this is an initial packet to us
    if key_id == *our_key_id {
        // Initial packet
        if data.len() < 96 {
            return Err(AdnlError::InvalidPacket("initial packet too short".into()));
        }

        let mut sender_pubkey = [0u8; 32];
        sender_pubkey.copy_from_slice(&data[32..64]);

        let mut checksum = [0u8; 32];
        checksum.copy_from_slice(&data[64..96]);

        let encrypted_content = &data[96..];

        // Calculate shared secret
        let shared_secret = ecdh(our_privkey, &sender_pubkey);

        // Derive decryption key and IV
        let (key, iv) = derive_packet_key(&shared_secret, &checksum);

        // Decrypt content
        let mut cipher = AesCtrCipher::new(key, iv);
        let decrypted_content = cipher.decrypt(encrypted_content);

        // Verify checksum
        let computed_checksum = sha256(&decrypted_content);
        if computed_checksum != checksum {
            return Err(AdnlError::ChecksumMismatch);
        }

        // Decode content
        let content = AdnlPacketContents::decode(&decrypted_content)?;

        Ok((
            UdpPacket::Initial {
                recipient_key_id: key_id,
                sender_pubkey,
                checksum,
                encrypted_content: encrypted_content.to_vec(),
            },
            content,
        ))
    } else {
        // This might be a channel packet - return error to let caller try channel decryption
        Err(AdnlError::InvalidPacket("unknown key ID - may be channel packet".into()))
    }
}

/// Decodes a channel packet.
///
/// # Arguments
///
/// * `data` - The raw packet data.
/// * `cipher` - The channel cipher for decryption.
///
/// # Returns
///
/// The decoded packet content.
#[allow(dead_code)]
pub fn decode_channel_packet(
    data: &[u8],
    cipher: &mut AesCtrCipher,
) -> Result<AdnlPacketContents> {
    if data.len() < 64 {
        return Err(AdnlError::InvalidPacket("channel packet too short".into()));
    }

    let mut checksum = [0u8; 32];
    checksum.copy_from_slice(&data[32..64]);

    let encrypted_content = &data[64..];

    // Decrypt content
    cipher.reset();
    let decrypted_content = cipher.decrypt(encrypted_content);

    // Verify checksum
    let computed_checksum = sha256(&decrypted_content);
    if computed_checksum != checksum {
        return Err(AdnlError::ChecksumMismatch);
    }

    // Decode content
    AdnlPacketContents::decode(&decrypted_content)
}

/// Derives encryption key and IV from shared secret and checksum.
fn derive_packet_key(shared_secret: &[u8; 32], checksum: &[u8; 32]) -> ([u8; 32], [u8; 16]) {
    // Key = shared_secret[0..16] || checksum[16..32]
    let mut key = [0u8; 32];
    key[..16].copy_from_slice(&shared_secret[..16]);
    key[16..].copy_from_slice(&checksum[16..]);

    // IV = checksum[0..4] || shared_secret[20..32]
    let mut iv = [0u8; 16];
    iv[..4].copy_from_slice(&checksum[..4]);
    iv[4..].copy_from_slice(&shared_secret[20..]);

    (key, iv)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ton_crypto::x25519::X25519Keypair;

    #[test]
    fn test_packet_flags() {
        let mut flags = AdnlPacketFlags::default();
        assert!(!flags.has(AdnlPacketFlags::FROM));

        flags.set(AdnlPacketFlags::FROM);
        assert!(flags.has(AdnlPacketFlags::FROM));

        flags.clear(AdnlPacketFlags::FROM);
        assert!(!flags.has(AdnlPacketFlags::FROM));
    }

    #[test]
    fn test_packet_contents_encode_decode() {
        let message = AdnlMessage::Custom {
            data: b"Hello, ADNL UDP!".to_vec(),
        };
        let mut content = AdnlPacketContents::with_message(message);
        content.set_seqno(42);

        let encoded = content.encode();
        let decoded = AdnlPacketContents::decode(&encoded).unwrap();

        assert!(decoded.message.is_some());
        assert_eq!(decoded.seqno, Some(42));

        if let Some(AdnlMessage::Custom { data }) = decoded.message {
            assert_eq!(data, b"Hello, ADNL UDP!");
        } else {
            panic!("Expected Custom message");
        }
    }

    #[test]
    fn test_message_encode_decode() {
        let messages = vec![
            AdnlMessage::CreateChannel {
                key: [1u8; 32],
                date: 12345,
            },
            AdnlMessage::ConfirmChannel {
                key: [2u8; 32],
                peer_key: [3u8; 32],
                date: 12346,
            },
            AdnlMessage::Query {
                query_id: [4u8; 32],
                query: b"test query".to_vec(),
            },
            AdnlMessage::Answer {
                query_id: [5u8; 32],
                answer: b"test answer".to_vec(),
            },
            AdnlMessage::Custom {
                data: b"custom data".to_vec(),
            },
            AdnlMessage::Part {
                hash: [6u8; 32],
                total_size: 1000,
                offset: 0,
                data: b"part data".to_vec(),
            },
        ];

        for msg in messages {
            let mut writer = TlWriter::new();
            encode_message(&mut writer, &msg);
            let encoded = writer.finish();

            let mut reader = TlReader::new(&encoded);
            let decoded = decode_message(&mut reader).unwrap();

            // Verify the message type matches
            assert_eq!(msg.schema_id(), decoded.schema_id());
        }
    }

    #[test]
    fn test_udp_packet_encode_decode() {
        let sender = X25519Keypair::generate();
        let recipient = X25519Keypair::generate();

        // Verify ECDH works symmetrically
        let shared1 = sender.ecdh(&recipient.public_key);
        let shared2 = recipient.ecdh(&sender.public_key);
        assert_eq!(shared1, shared2, "ECDH shared secrets should match");

        let message = AdnlMessage::Custom {
            data: b"Test UDP packet".to_vec(),
        };
        let content = AdnlPacketContents::with_message(message);

        // Encode
        let packet = encode_udp_packet(
            &content,
            &recipient.public_key,
            &sender.private_key,
            &sender.public_key,
        );

        // Decode - use recipient's private key
        let recipient_key_id = calculate_key_id(&recipient.public_key);

        // Extract the sender pubkey from the packet to verify ECDH computation
        let sender_pubkey_from_packet: [u8; 32] = packet[32..64].try_into().unwrap();
        assert_eq!(sender_pubkey_from_packet, sender.public_key);

        let (udp_packet, decoded_content) = decode_udp_packet(
            &packet,
            &recipient_key_id,
            &recipient.private_key,
        ).unwrap();

        // Verify
        if let UdpPacket::Initial { sender_pubkey, .. } = udp_packet {
            assert_eq!(sender_pubkey, sender.public_key);
        } else {
            panic!("Expected Initial packet");
        }

        if let Some(AdnlMessage::Custom { data }) = decoded_content.message {
            assert_eq!(data, b"Test UDP packet");
        } else {
            panic!("Expected Custom message");
        }
    }

    #[test]
    fn test_channel_packet_encode_decode() {
        use super::super::AdnlChannel;

        // Set up a channel
        let (mut alice_channel, alice_pubkey, alice_date) = AdnlChannel::new_pending();
        let (mut bob_channel, bob_pubkey, bob_date) = AdnlChannel::from_create_channel(
            &alice_pubkey,
            alice_date,
        );
        alice_channel.confirm(&bob_pubkey, bob_date);

        let channel_key_id = *alice_channel.out_channel_id();

        // Create and encode a message
        let message = AdnlMessage::Custom {
            data: b"Channel message".to_vec(),
        };
        let content = AdnlPacketContents::with_message(message);

        // Actually use the channel's encrypt method
        alice_channel.reset_ciphers();
        let encoded = alice_channel.encrypt(&content.encode());
        let checksum = sha256(&content.encode());

        let mut packet = Vec::with_capacity(64 + encoded.len());
        packet.extend_from_slice(&channel_key_id);
        packet.extend_from_slice(&checksum);
        packet.extend_from_slice(&encoded);

        // Decode using Bob's cipher
        bob_channel.reset_ciphers();
        let decrypted = bob_channel.decrypt(&packet[64..]);
        let computed_checksum = sha256(&decrypted);
        assert_eq!(computed_checksum, checksum);

        let decoded_content = AdnlPacketContents::decode(&decrypted).unwrap();
        if let Some(AdnlMessage::Custom { data }) = decoded_content.message {
            assert_eq!(data, b"Channel message");
        } else {
            panic!("Expected Custom message");
        }
    }
}
