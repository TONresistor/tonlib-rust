//! ADNL TCP client implementation.
//!
//! This module provides an async client for connecting to TON liteservers
//! using the ADNL TCP protocol.

use std::net::SocketAddr;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tracing::{debug, trace};

use ton_crypto::aes_ctr::AesCtrCipher;

use crate::error::{AdnlError, Result};
use crate::handshake::{perform_handshake, SessionCiphers, HANDSHAKE_PACKET_SIZE};
use crate::packet::{
    create_ping, decode_packet, encode_packet, encrypt_packet,
    generate_query_id, parse_pong, wrap_liteserver_query, unwrap_liteserver_response,
    MAX_PACKET_SIZE,
};

/// Default timeout for operations (30 seconds).
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// Default ping interval (5 seconds).
pub const DEFAULT_PING_INTERVAL: Duration = Duration::from_secs(5);

/// ADNL TCP client for communicating with TON liteservers.
///
/// # Example
///
/// ```rust,no_run
/// use std::net::SocketAddr;
/// use ton_adnl::AdnlClient;
///
/// async fn example() -> Result<(), Box<dyn std::error::Error>> {
///     let addr: SocketAddr = "1.2.3.4:12345".parse()?;
///     let server_pubkey = [0u8; 32]; // Replace with actual server pubkey
///
///     let mut client = AdnlClient::connect(addr, &server_pubkey).await?;
///
///     // Send a ping
///     client.ping().await?;
///
///     // Send a query
///     let response = client.query(&[/* query data */]).await?;
///
///     Ok(())
/// }
/// ```
pub struct AdnlClient {
    /// The TCP stream.
    stream: TcpStream,
    /// Cipher for receiving (decrypting) packets.
    recv_cipher: tokio::sync::Mutex<AesCtrCipher>,
    /// Cipher for sending (encrypting) packets.
    send_cipher: tokio::sync::Mutex<AesCtrCipher>,
    /// Connection timeout.
    timeout: Duration,
}

impl AdnlClient {
    /// Connects to a liteserver and performs the ADNL handshake.
    ///
    /// # Arguments
    ///
    /// * `addr` - The socket address of the liteserver.
    /// * `server_pubkey` - The server's Ed25519 public key (32 bytes).
    ///
    /// # Returns
    ///
    /// An established ADNL client ready for communication.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Connection fails
    /// - Handshake fails
    /// - Server doesn't respond with empty ADNL packet
    pub async fn connect(addr: SocketAddr, server_pubkey: &[u8; 32]) -> Result<Self> {
        Self::connect_with_timeout(addr, server_pubkey, DEFAULT_TIMEOUT).await
    }

    /// Connects to a liteserver with a custom timeout.
    pub async fn connect_with_timeout(
        addr: SocketAddr,
        server_pubkey: &[u8; 32],
        connect_timeout: Duration,
    ) -> Result<Self> {
        debug!("Connecting to liteserver at {}", addr);

        // Connect with timeout
        let stream = timeout(connect_timeout, TcpStream::connect(addr))
            .await
            .map_err(|_| AdnlError::HandshakeFailed("connection timeout".into()))?
            .map_err(AdnlError::Io)?;

        // Disable Nagle's algorithm for lower latency
        stream.set_nodelay(true)?;

        debug!("TCP connection established, performing handshake");

        // Perform handshake - generates ephemeral keypair internally for ECDH
        let (handshake_packet, ciphers) = perform_handshake(server_pubkey)
            .map_err(|e| AdnlError::HandshakeFailed(format!("Key conversion failed: {}", e)))?;

        Self::complete_handshake(stream, handshake_packet, ciphers, connect_timeout).await
    }

    /// Completes the handshake after TCP connection is established.
    async fn complete_handshake(
        mut stream: TcpStream,
        handshake_packet: [u8; HANDSHAKE_PACKET_SIZE],
        ciphers: SessionCiphers,
        op_timeout: Duration,
    ) -> Result<Self> {
        // Send handshake packet
        timeout(op_timeout, stream.write_all(&handshake_packet))
            .await
            .map_err(|_| AdnlError::HandshakeFailed("send timeout".into()))?
            .map_err(AdnlError::Io)?;

        trace!("Handshake packet sent ({} bytes)", handshake_packet.len());

        // Create client with ciphers
        let mut client = Self {
            stream,
            recv_cipher: tokio::sync::Mutex::new(ciphers.recv_cipher),
            send_cipher: tokio::sync::Mutex::new(ciphers.send_cipher),
            timeout: op_timeout,
        };

        // Wait for empty ADNL packet confirmation
        let response = timeout(op_timeout, client.recv_packet_internal())
            .await
            .map_err(|_| AdnlError::HandshakeFailed("confirmation timeout".into()))??;

        // Response should be empty (just nonce + checksum)
        if !response.is_empty() {
            debug!("Unexpected handshake response: {} bytes", response.len());
        }

        debug!("Handshake completed successfully");
        Ok(client)
    }

    /// Sends a query to the liteserver and waits for a response.
    ///
    /// The query is automatically wrapped in the required TL structures
    /// (liteServer.query and adnl.message.query).
    ///
    /// # Arguments
    ///
    /// * `data` - The raw query data (e.g., liteServer.getMasterchainInfo).
    ///
    /// # Returns
    ///
    /// The response data (unwrapped from adnl.message.answer).
    pub async fn query(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        self.query_with_timeout(data, self.timeout).await
    }

    /// Sends a query with a custom timeout.
    pub async fn query_with_timeout(
        &mut self,
        data: &[u8],
        query_timeout: Duration,
    ) -> Result<Vec<u8>> {
        let query_id = generate_query_id();

        trace!("Sending query with id {:02x?}...", &query_id[..4]);

        // Wrap the query
        let wrapped = wrap_liteserver_query(data, &query_id);

        // Send the packet
        self.send_packet(&wrapped).await?;

        // Wait for response
        let response = timeout(query_timeout, self.recv_packet_internal())
            .await
            .map_err(|_| AdnlError::QueryTimeout)??;

        // Unwrap the response
        let (_resp_query_id, answer) = unwrap_liteserver_response(&response, Some(&query_id))?;

        trace!("Received response: {} bytes", answer.len());
        Ok(answer)
    }

    /// Sends a raw query without wrapping.
    ///
    /// Use this when you need to send a pre-wrapped query.
    pub async fn send_raw_query(&mut self, data: &[u8]) -> Result<()> {
        self.send_packet(data).await
    }

    /// Receives a raw response without unwrapping.
    pub async fn recv_raw_response(&mut self) -> Result<Vec<u8>> {
        self.recv_packet_internal().await
    }

    /// Sends a ping to the server.
    ///
    /// This should be called periodically (every ~5 seconds) to keep
    /// the connection alive.
    pub async fn ping(&mut self) -> Result<()> {
        self.ping_with_timeout(self.timeout).await
    }

    /// Sends a ping with a custom timeout.
    pub async fn ping_with_timeout(&mut self, ping_timeout: Duration) -> Result<()> {
        let ping_data = create_ping();

        trace!("Sending ping");
        self.send_packet(&ping_data).await?;

        // Wait for pong
        let response = timeout(ping_timeout, self.recv_packet_internal())
            .await
            .map_err(|_| AdnlError::QueryTimeout)??;

        let _pong_id = parse_pong(&response)?;
        trace!("Received pong");

        Ok(())
    }

    /// Sends an empty packet (keepalive) to test encryption.
    #[allow(dead_code)]
    pub async fn send_empty_packet(&mut self) -> Result<()> {
        self.send_packet(&[]).await
    }

    /// Sends a packet to the server.
    pub async fn send_packet(&mut self, payload: &[u8]) -> Result<()> {
        // Encode the packet
        let packet = encode_packet(payload);

        // Encrypt the packet
        let encrypted = {
            let mut cipher = self.send_cipher.lock().await;
            encrypt_packet(&packet, &mut cipher)
        };

        // Send the packet
        self.stream.write_all(&encrypted).await?;
        self.stream.flush().await?;

        Ok(())
    }

    /// Receives a packet from the server.
    async fn recv_packet_internal(&mut self) -> Result<Vec<u8>> {
        // Read the size (4 bytes, encrypted)
        let mut size_buf = [0u8; 4];
        self.stream.read_exact(&mut size_buf).await?;

        // Decrypt the size
        let decrypted_size = {
            let mut cipher = self.recv_cipher.lock().await;
            cipher.decrypt(&size_buf)
        };

        let size = u32::from_le_bytes([
            decrypted_size[0],
            decrypted_size[1],
            decrypted_size[2],
            decrypted_size[3],
        ]) as usize;

        if size > MAX_PACKET_SIZE {
            return Err(AdnlError::PacketTooLarge {
                size,
                max: MAX_PACKET_SIZE,
            });
        }

        if size < 64 {
            return Err(AdnlError::InvalidPacket(format!(
                "packet too small: {} bytes",
                size
            )));
        }

        // Read the rest of the packet
        let mut encrypted_body = vec![0u8; size];
        self.stream.read_exact(&mut encrypted_body).await?;

        // Decrypt the body
        let decrypted_body = {
            let mut cipher = self.recv_cipher.lock().await;
            cipher.decrypt(&encrypted_body)
        };

        // Reconstruct full packet for decode_packet
        let mut full_packet = Vec::with_capacity(4 + size);
        full_packet.extend_from_slice(&decrypted_size);
        full_packet.extend_from_slice(&decrypted_body);

        // Decode and verify checksum
        decode_packet(&full_packet)
    }

    /// Receives a packet with a timeout.
    pub async fn recv_packet(&mut self) -> Result<Vec<u8>> {
        timeout(self.timeout, self.recv_packet_internal())
            .await
            .map_err(|_| AdnlError::QueryTimeout)?
    }

    /// Sets the default timeout for operations.
    pub fn set_timeout(&mut self, timeout: Duration) {
        self.timeout = timeout;
    }

    /// Returns the current timeout.
    pub fn timeout(&self) -> Duration {
        self.timeout
    }

    /// Returns the local address of the connection.
    pub fn local_addr(&self) -> Result<SocketAddr> {
        self.stream.local_addr().map_err(AdnlError::Io)
    }

    /// Returns the peer address of the connection.
    pub fn peer_addr(&self) -> Result<SocketAddr> {
        self.stream.peer_addr().map_err(AdnlError::Io)
    }

    /// Gracefully shuts down the connection.
    pub async fn shutdown(&mut self) -> Result<()> {
        self.stream.shutdown().await.map_err(AdnlError::Io)
    }
}

impl std::fmt::Debug for AdnlClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AdnlClient")
            .field("peer_addr", &self.stream.peer_addr().ok())
            .field("timeout", &self.timeout)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_timeout() {
        assert_eq!(DEFAULT_TIMEOUT, Duration::from_secs(30));
    }

    #[test]
    fn test_default_ping_interval() {
        assert_eq!(DEFAULT_PING_INTERVAL, Duration::from_secs(5));
    }
}
