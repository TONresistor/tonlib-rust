//! ADNL packet encoding and decoding.
//!
//! After the handshake, all communication uses encrypted ADNL packets:
//!
//! ```text
//! +----------+----------+----------------------+-------------+
//! |  Size    |  Nonce   |      Payload         |  Checksum   |
//! | 4 bytes  | 32 bytes |    N-64 bytes        |  32 bytes   |
//! | (LE u32) | (random) |                      |  (SHA256)   |
//! +----------+----------+----------------------+-------------+
//! ```
//!
//! - Size: Little-endian u32, total size of (nonce + payload + checksum)
//! - Everything after size is encrypted with AES-CTR
//! - Checksum = SHA256(nonce || payload)

use rand::RngCore;
use ton_crypto::{aes_ctr::AesCtrCipher, sha256::sha256};

use crate::error::{AdnlError, Result};
use crate::tl::{TlReader, TlWriter, ADNL_MESSAGE_ANSWER, ADNL_MESSAGE_QUERY, TCP_PING, TCP_PONG};

/// Size of the nonce in ADNL packets.
pub const NONCE_SIZE: usize = 32;

/// Size of the checksum in ADNL packets.
pub const CHECKSUM_SIZE: usize = 32;

/// Overhead per packet (nonce + checksum).
pub const PACKET_OVERHEAD: usize = NONCE_SIZE + CHECKSUM_SIZE;

/// Maximum allowed packet size (10 MB).
pub const MAX_PACKET_SIZE: usize = 10 * 1024 * 1024;

/// Minimum packet size (nonce + checksum with empty payload).
pub const MIN_PACKET_SIZE: usize = PACKET_OVERHEAD;

/// Encodes a payload into an ADNL packet (before encryption).
///
/// The packet format is:
/// - 4 bytes: size (little-endian u32, not included in size itself)
/// - 32 bytes: random nonce
/// - N bytes: payload
/// - 32 bytes: checksum (SHA256 of nonce || payload)
///
/// # Arguments
///
/// * `payload` - The data to encode.
///
/// # Returns
///
/// The complete packet including the 4-byte size prefix.
pub fn encode_packet(payload: &[u8]) -> Vec<u8> {
    let mut nonce = [0u8; NONCE_SIZE];
    rand::thread_rng().fill_bytes(&mut nonce);

    encode_packet_with_nonce(payload, &nonce)
}

/// Encodes a payload into an ADNL packet with a specific nonce.
///
/// This is useful for testing where you need deterministic output.
pub fn encode_packet_with_nonce(payload: &[u8], nonce: &[u8; NONCE_SIZE]) -> Vec<u8> {
    // Calculate checksum: SHA256(nonce || payload)
    let mut checksum_data = Vec::with_capacity(NONCE_SIZE + payload.len());
    checksum_data.extend_from_slice(nonce);
    checksum_data.extend_from_slice(payload);
    let checksum = sha256(&checksum_data);

    // Build packet
    let inner_size = NONCE_SIZE + payload.len() + CHECKSUM_SIZE;
    let mut packet = Vec::with_capacity(4 + inner_size);

    // Size (little-endian u32)
    packet.extend_from_slice(&(inner_size as u32).to_le_bytes());

    // Nonce
    packet.extend_from_slice(nonce);

    // Payload
    packet.extend_from_slice(payload);

    // Checksum
    packet.extend_from_slice(&checksum);

    packet
}

/// Encrypts a packet using the session cipher.
///
/// The entire packet (including size prefix) is encrypted with AES-CTR.
///
/// # Arguments
///
/// * `packet` - The packet to encrypt (including size prefix).
/// * `cipher` - The send cipher.
///
/// # Returns
///
/// The encrypted packet.
pub fn encrypt_packet(packet: &[u8], cipher: &mut AesCtrCipher) -> Vec<u8> {
    cipher.encrypt(packet)
}

/// Decrypts a packet using the session cipher.
///
/// The entire packet (including size prefix) is decrypted with AES-CTR.
///
/// # Arguments
///
/// * `packet` - The encrypted packet (including size prefix).
/// * `cipher` - The receive cipher.
///
/// # Returns
///
/// The decrypted packet.
pub fn decrypt_packet(packet: &[u8], cipher: &mut AesCtrCipher) -> Vec<u8> {
    // Decryption is the same operation as encryption in CTR mode
    cipher.decrypt(packet)
}

/// Validates and decodes a decrypted ADNL packet.
///
/// Verifies the checksum and extracts the payload.
///
/// # Arguments
///
/// * `packet` - The decrypted packet (including size prefix).
///
/// # Returns
///
/// The payload data.
pub fn decode_packet(packet: &[u8]) -> Result<Vec<u8>> {
    if packet.len() < 4 {
        return Err(AdnlError::InvalidPacket("packet too short".into()));
    }

    let size = u32::from_le_bytes([packet[0], packet[1], packet[2], packet[3]]) as usize;

    if size > MAX_PACKET_SIZE {
        return Err(AdnlError::PacketTooLarge {
            size,
            max: MAX_PACKET_SIZE,
        });
    }

    if size < MIN_PACKET_SIZE {
        return Err(AdnlError::InvalidPacket(format!(
            "packet too small: {} bytes",
            size
        )));
    }

    if packet.len() < 4 + size {
        return Err(AdnlError::InvalidPacket("incomplete packet".into()));
    }

    let inner = &packet[4..4 + size];

    // Extract components
    let nonce = &inner[0..NONCE_SIZE];
    let payload_end = size - CHECKSUM_SIZE;
    let payload = &inner[NONCE_SIZE..payload_end];
    let checksum = &inner[payload_end..];

    // Verify checksum
    let mut checksum_data = Vec::with_capacity(NONCE_SIZE + payload.len());
    checksum_data.extend_from_slice(nonce);
    checksum_data.extend_from_slice(payload);
    let expected_checksum = sha256(&checksum_data);

    if checksum != expected_checksum {
        return Err(AdnlError::ChecksumMismatch);
    }

    Ok(payload.to_vec())
}

/// Creates a TCP ping packet.
///
/// Schema: `tcp.ping random_id:long = tcp.Pong`
///
/// # Returns
///
/// The TL-encoded ping message.
pub fn create_ping() -> Vec<u8> {
    let random_id: u64 = rand::random();
    create_ping_with_id(random_id)
}

/// Creates a TCP ping packet with a specific random ID.
pub fn create_ping_with_id(random_id: u64) -> Vec<u8> {
    let mut writer = TlWriter::new();
    writer.write_u32(TCP_PING);
    writer.write_u64(random_id);
    writer.finish()
}

/// Parses a TCP pong response.
///
/// Schema: `tcp.pong random_id:long = tcp.Pong`
///
/// # Returns
///
/// The random_id from the pong, or an error if parsing fails.
pub fn parse_pong(data: &[u8]) -> Result<u64> {
    if data.len() < 12 {
        return Err(AdnlError::InvalidPacket("pong too short".into()));
    }

    let type_id = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    if type_id != TCP_PONG {
        return Err(AdnlError::UnexpectedMessageType(type_id));
    }

    let random_id = u64::from_le_bytes([
        data[4], data[5], data[6], data[7],
        data[8], data[9], data[10], data[11],
    ]);

    Ok(random_id)
}

/// Wraps a query for sending over ADNL.
///
/// The query is wrapped in:
/// - adnl.message.query { query_id: int256, query: bytes } (0x7af98bb4)
///
/// Note: The liteServer.query wrapper should be applied by the caller
/// (e.g., LiteClient) before calling this function.
///
/// # Arguments
///
/// * `query` - The query data (already wrapped in liteServer.query for liteserver queries).
/// * `query_id` - The 32-byte query ID for tracking responses.
///
/// # Returns
///
/// The query wrapped in adnl.message.query.
pub fn wrap_liteserver_query(query: &[u8], query_id: &[u8; 32]) -> Vec<u8> {
    // Wrap in adnl.message.query
    let mut adnl_query = TlWriter::new();
    adnl_query.write_u32(ADNL_MESSAGE_QUERY);
    adnl_query.write_int256(query_id);
    adnl_query.write_bytes(query);

    adnl_query.finish()
}

/// Unwraps a response from a liteserver.
///
/// The response is expected to be:
/// - adnl.message.answer { query_id: int256, answer: bytes } (0x1684ac0f)
///
/// # Arguments
///
/// * `data` - The raw response data.
/// * `expected_query_id` - The expected query ID (optional).
///
/// # Returns
///
/// A tuple of (query_id, answer_data).
pub fn unwrap_liteserver_response(
    data: &[u8],
    expected_query_id: Option<&[u8; 32]>,
) -> Result<([u8; 32], Vec<u8>)> {
    let mut reader = TlReader::new(data);

    // Read message type
    let type_id = reader.read_u32()?;
    if type_id != ADNL_MESSAGE_ANSWER {
        return Err(AdnlError::UnexpectedMessageType(type_id));
    }

    // Read query ID
    let query_id = reader.read_int256()?;

    // Verify query ID if expected
    if let Some(expected) = expected_query_id && &query_id != expected {
        return Err(AdnlError::QueryIdMismatch);
    }

    // Read answer bytes
    let answer = reader.read_bytes()?;

    Ok((query_id, answer))
}

/// Generates a random query ID.
pub fn generate_query_id() -> [u8; 32] {
    let mut query_id = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut query_id);
    query_id
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_decode_packet() {
        let payload = b"Hello, ADNL!";
        let packet = encode_packet(payload);

        let decoded = decode_packet(&packet).unwrap();
        assert_eq!(decoded, payload);
    }

    #[test]
    fn test_packet_structure() {
        let payload = b"Test payload";
        let nonce = [42u8; NONCE_SIZE];
        let packet = encode_packet_with_nonce(payload, &nonce);

        // Check size
        let size = u32::from_le_bytes([packet[0], packet[1], packet[2], packet[3]]) as usize;
        assert_eq!(size, NONCE_SIZE + payload.len() + CHECKSUM_SIZE);

        // Check nonce
        assert_eq!(&packet[4..36], &nonce);

        // Check payload
        assert_eq!(&packet[36..36 + payload.len()], payload);
    }

    #[test]
    fn test_encrypt_decrypt_packet() {
        let payload = b"Secret message";
        let packet = encode_packet(payload);

        // Create cipher pair
        let key = [1u8; 32];
        let iv = [2u8; 16];

        let mut encrypt_cipher = AesCtrCipher::new(key, iv);
        let encrypted = encrypt_packet(&packet, &mut encrypt_cipher);

        // Entire packet should be different (including size prefix)
        assert_ne!(encrypted, packet);

        // Decrypt
        let mut decrypt_cipher = AesCtrCipher::new(key, iv);
        let decrypted = decrypt_packet(&encrypted, &mut decrypt_cipher);

        assert_eq!(decrypted, packet);

        // Decode
        let decoded = decode_packet(&decrypted).unwrap();
        assert_eq!(decoded, payload);
    }

    #[test]
    fn test_checksum_verification() {
        let payload = b"Test";
        let mut packet = encode_packet(payload);

        // Corrupt the payload
        packet[40] ^= 0xFF;

        let result = decode_packet(&packet);
        assert!(matches!(result, Err(AdnlError::ChecksumMismatch)));
    }

    #[test]
    fn test_ping_pong() {
        let random_id = 12345u64;
        let ping = create_ping_with_id(random_id);

        // Check ping structure
        let type_id = u32::from_le_bytes([ping[0], ping[1], ping[2], ping[3]]);
        assert_eq!(type_id, TCP_PING);

        // Create fake pong
        let mut pong = Vec::new();
        pong.extend_from_slice(&TCP_PONG.to_le_bytes());
        pong.extend_from_slice(&random_id.to_le_bytes());

        let parsed_id = parse_pong(&pong).unwrap();
        assert_eq!(parsed_id, random_id);
    }

    #[test]
    fn test_wrap_unwrap_query() {
        let query = b"test query data";
        let query_id = [42u8; 32];

        let wrapped = wrap_liteserver_query(query, &query_id);

        // Check it starts with adnl.message.query
        let type_id = u32::from_le_bytes([wrapped[0], wrapped[1], wrapped[2], wrapped[3]]);
        assert_eq!(type_id, ADNL_MESSAGE_QUERY);

        // Check query_id follows
        assert_eq!(&wrapped[4..36], &query_id);
    }

    #[test]
    fn test_empty_payload() {
        let payload: &[u8] = &[];
        let packet = encode_packet(payload);

        let decoded = decode_packet(&packet).unwrap();
        assert!(decoded.is_empty());
    }

    #[test]
    fn test_large_payload() {
        let payload: Vec<u8> = (0..10000).map(|i| (i % 256) as u8).collect();
        let packet = encode_packet(&payload);

        let decoded = decode_packet(&packet).unwrap();
        assert_eq!(decoded, payload);
    }

    #[test]
    fn test_packet_too_large() {
        // Create a packet with claimed size larger than max
        let mut packet = Vec::new();
        let huge_size = (MAX_PACKET_SIZE + 1) as u32;
        packet.extend_from_slice(&huge_size.to_le_bytes());
        packet.extend_from_slice(&[0u8; 100]);

        let result = decode_packet(&packet);
        assert!(matches!(result, Err(AdnlError::PacketTooLarge { .. })));
    }

    #[test]
    fn test_generate_query_id() {
        let id1 = generate_query_id();
        let id2 = generate_query_id();

        // Should be different (with overwhelming probability)
        assert_ne!(id1, id2);
    }
}

#[cfg(test)]
mod pytoniq_compat_tests {
    use super::*;
    use ton_crypto::sha256::sha256;
    
    #[test]
    fn test_checksum_matches_pytoniq() {
        // Same values as Python test
        let nonce: Vec<u8> = (0u8..32).collect();
        let payload: Vec<u8> = vec![0x4d, 0x08, 0x2b, 0x9a, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        
        // Compute checksum same way as pytoniq
        let mut checksum_data = Vec::new();
        checksum_data.extend_from_slice(&nonce);
        checksum_data.extend_from_slice(&payload);
        let checksum = sha256(&checksum_data);
        
        // Expected from pytoniq
        let expected = [
            0xc7, 0xaa, 0x96, 0xce, 0x2e, 0xfc, 0xbe, 0x39,
            0xe7, 0xc0, 0xf6, 0xd4, 0x32, 0x70, 0x11, 0x57,
            0x67, 0x6c, 0x83, 0x04, 0xf9, 0x7f, 0xa2, 0x2c,
            0x5d, 0xba, 0xb2, 0xf0, 0x29, 0xbb, 0x90, 0xe3
        ];
        
        println!("Rust checksum: {:02x?}", &checksum[..]);
        println!("Expected:      {:02x?}", &expected[..]);
        
        assert_eq!(checksum, expected, "SHA256 checksum must match pytoniq");
    }
    
    #[test]
    fn test_packet_structure_matches_pytoniq() {
        let payload: Vec<u8> = vec![0x4d, 0x08, 0x2b, 0x9a, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let nonce: [u8; 32] = core::array::from_fn(|i| i as u8);
        
        let packet = encode_packet_with_nonce(&payload, &nonce);
        
        // Verify size field
        let size = u32::from_le_bytes([packet[0], packet[1], packet[2], packet[3]]);
        assert_eq!(size, 76, "Size should be 76 (32 nonce + 12 payload + 32 checksum)");
        
        // Total packet should be 80 bytes
        assert_eq!(packet.len(), 80, "Total packet should be 80 bytes");
        
        // Verify size field bytes match pytoniq
        assert_eq!(&packet[0..4], &[0x4c, 0x00, 0x00, 0x00], "Size field bytes");
        
        // Verify checksum matches
        let expected_checksum = [
            0xc7, 0xaa, 0x96, 0xce, 0x2e, 0xfc, 0xbe, 0x39,
            0xe7, 0xc0, 0xf6, 0xd4, 0x32, 0x70, 0x11, 0x57,
            0x67, 0x6c, 0x83, 0x04, 0xf9, 0x7f, 0xa2, 0x2c,
            0x5d, 0xba, 0xb2, 0xf0, 0x29, 0xbb, 0x90, 0xe3
        ];
        assert_eq!(&packet[48..80], &expected_checksum[..], "Checksum must match pytoniq");
    }
}
