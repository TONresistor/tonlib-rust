//! UDP ADNL Transport for TON Sites.
//!
//! This module provides the real network transport using ADNL over UDP
//! combined with RLDP for reliable data transfer.
//!
//! # Architecture
//!
//! ```text
//! SiteClient
//!     |
//!     v
//! UdpRldpTransport
//!     |
//!     +--> AdnlNode (UDP socket, peer management)
//!     |
//!     +--> OutgoingTransfer (FEC encoding)
//!     |
//!     +--> IncomingTransfer (FEC decoding)
//! ```

#![cfg(feature = "udp-transport")]

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::Mutex;
use tracing::{debug, trace, warn};

use ton_adnl::udp::{AdnlMessage, AdnlNode};
use ton_crypto::ed25519::Ed25519Keypair;
use ton_rldp::{
    IncomingTransfer, OutgoingTransfer, RldpComplete, RldpMessagePart,
    create_query, parse_answer, RLDP_COMPLETE, RLDP_MESSAGE_PART,
};
use ton_adnl::TlReader;

use crate::error::{SiteError, SiteResult};
use crate::types::{
    FullHttpResponse, GetNextPayloadPart, HttpRequest, HttpResponse, PayloadPart,
};

/// Default RLDP query timeout.
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// Maximum response size (10 MB).
const MAX_RESPONSE_SIZE: i64 = 10 * 1024 * 1024;

/// UDP RLDP Transport configuration.
#[derive(Debug, Clone)]
pub struct UdpTransportConfig {
    /// Query timeout.
    pub timeout: Duration,
    /// Maximum response size.
    pub max_response_size: i64,
    /// Chunk size for payload transfers.
    pub chunk_size: usize,
}

impl Default for UdpTransportConfig {
    fn default() -> Self {
        Self {
            timeout: DEFAULT_TIMEOUT,
            max_response_size: MAX_RESPONSE_SIZE,
            chunk_size: 128 * 1024,
        }
    }
}

/// UDP RLDP Transport for TON Sites.
///
/// This transport uses ADNL over UDP with RLDP for reliable transfers.
pub struct UdpRldpTransport {
    /// The ADNL node for network communication.
    node: Arc<Mutex<AdnlNode>>,
    /// Connected peer addresses.
    peers: HashMap<[u8; 32], SocketAddr>,
    /// Configuration.
    config: UdpTransportConfig,
}

impl UdpRldpTransport {
    /// Creates a new UDP RLDP transport bound to the specified address.
    pub async fn bind(addr: SocketAddr) -> SiteResult<Self> {
        let node = AdnlNode::bind(addr)
            .await
            .map_err(|e| SiteError::ConnectionFailed(e.to_string()))?;

        Ok(Self {
            node: Arc::new(Mutex::new(node)),
            peers: HashMap::new(),
            config: UdpTransportConfig::default(),
        })
    }

    /// Creates a new transport with a specific keypair.
    pub async fn with_keypair(addr: SocketAddr, keypair: Ed25519Keypair) -> SiteResult<Self> {
        let socket = tokio::net::UdpSocket::bind(addr)
            .await
            .map_err(|e| SiteError::ConnectionFailed(e.to_string()))?;

        let node = AdnlNode::with_keypair(socket, keypair)
            .map_err(|e| SiteError::ConnectionFailed(e.to_string()))?;

        Ok(Self {
            node: Arc::new(Mutex::new(node)),
            peers: HashMap::new(),
            config: UdpTransportConfig::default(),
        })
    }

    /// Returns the local ADNL public key.
    pub async fn public_key(&self) -> [u8; 32] {
        let node = self.node.lock().await;
        *node.public_key()
    }

    /// Connects to a TON site by ADNL address.
    pub async fn connect(
        &mut self,
        addr: SocketAddr,
        pubkey: &[u8; 32],
    ) -> SiteResult<UdpSiteConnection> {
        let peer_id = {
            let mut node = self.node.lock().await;
            node.add_peer(addr, pubkey)
                .await
                .map_err(|e| SiteError::ConnectionFailed(e.to_string()))?;
            node.get_peer_id(pubkey)
        };

        self.peers.insert(peer_id, addr);

        Ok(UdpSiteConnection {
            node: Arc::clone(&self.node),
            peer_id,
            config: self.config.clone(),
        })
    }
}

/// A UDP connection to a TON Site.
pub struct UdpSiteConnection {
    /// The shared ADNL node.
    node: Arc<Mutex<AdnlNode>>,
    /// The peer's key ID.
    peer_id: [u8; 32],
    /// Configuration.
    config: UdpTransportConfig,
}

impl UdpSiteConnection {
    /// Returns the peer's key ID.
    pub fn peer_id(&self) -> &[u8; 32] {
        &self.peer_id
    }

    /// Makes a GET request.
    pub async fn get(&self, path: &str) -> SiteResult<FullHttpResponse> {
        let request = HttpRequest::get(path);
        self.request(request).await
    }

    /// Makes a POST request with body.
    pub async fn post(
        &self,
        path: &str,
        body: Vec<u8>,
        content_type: &str,
    ) -> SiteResult<FullHttpResponse> {
        let request = HttpRequest::post(path)
            .with_content_type(content_type)
            .with_content_length(body.len());
        self.request_with_body(request, body).await
    }

    /// Sends an HTTP request and receives the response.
    pub async fn request(&self, request: HttpRequest) -> SiteResult<FullHttpResponse> {
        let request_id = request.id;
        let request_data = request.to_tl_bytes();

        // Send via RLDP query
        let response_data = self.rldp_query(&request_data).await?;

        // Parse response
        let (response, _) = HttpResponse::from_tl_bytes(&response_data)?;

        // Get body if present
        let body = if !response.no_payload {
            self.get_response_body(&request_id).await?
        } else {
            vec![]
        };

        Ok(FullHttpResponse::new(response, body))
    }

    /// Sends an HTTP request with body.
    pub async fn request_with_body(
        &self,
        request: HttpRequest,
        body: Vec<u8>,
    ) -> SiteResult<FullHttpResponse> {
        let request_id = request.id;
        let request_data = request.to_tl_bytes();

        // Send request via RLDP
        let response_data = self.rldp_query_with_body(&request_data, &body).await?;

        // Parse response
        let (response, _) = HttpResponse::from_tl_bytes(&response_data)?;

        // Get response body if present
        let response_body = if !response.no_payload {
            self.get_response_body(&request_id).await?
        } else {
            vec![]
        };

        Ok(FullHttpResponse::new(response, response_body))
    }

    /// Sends an RLDP query and receives the response.
    async fn rldp_query(&self, data: &[u8]) -> SiteResult<Vec<u8>> {
        // Create RLDP query wrapper
        let (query, query_bytes) = create_query(
            data,
            self.config.max_response_size,
            self.config.timeout.as_millis() as i32,
        );

        // Send via RLDP transfer
        let response_bytes = self.send_rldp_transfer(&query_bytes).await?;

        // Parse RLDP answer
        let answer = parse_answer(&response_bytes)
            .map_err(|e| SiteError::RldpError(format!("Failed to parse RLDP answer: {}", e)))?;

        // Verify query ID
        if answer.query_id != query.query_id {
            return Err(SiteError::RldpError("RLDP query ID mismatch".to_string()));
        }

        Ok(answer.data)
    }

    /// Sends an RLDP query with request body handling.
    async fn rldp_query_with_body(&self, data: &[u8], body: &[u8]) -> SiteResult<Vec<u8>> {
        // For now, concatenate request data with body for simple cases
        // A full implementation would handle bidirectional getNextPayloadPart flow
        let mut combined = data.to_vec();
        combined.extend_from_slice(body);

        self.rldp_query(&combined).await
    }

    /// Sends data via RLDP transfer and receives response.
    async fn send_rldp_transfer(&self, data: &[u8]) -> SiteResult<Vec<u8>> {
        // Create outgoing transfer with FEC encoding
        let mut outgoing = OutgoingTransfer::new(data);
        let transfer_id = outgoing.transfer_id;

        debug!(
            "Starting RLDP transfer {}, {} bytes",
            hex::encode(&transfer_id[..8]),
            data.len()
        );

        // Get initial burst of message parts
        let burst = outgoing.initial_burst();

        // Send all parts via ADNL custom messages
        {
            let mut node = self.node.lock().await;

            for part in &burst {
                let part_bytes = part.to_bytes();
                node.send_custom(&self.peer_id, &part_bytes)
                    .await
                    .map_err(|e| SiteError::ConnectionFailed(e.to_string()))?;

                trace!("Sent RLDP message part seqno={}", part.seqno);
            }
        }

        // Now receive the response transfer
        let mut incoming: Option<IncomingTransfer> = None;
        let deadline = tokio::time::Instant::now() + self.config.timeout;

        loop {
            if tokio::time::Instant::now() > deadline {
                return Err(SiteError::Timeout);
            }

            // Receive next ADNL message
            let (message, _sender_id) = {
                let mut node = self.node.lock().await;
                match tokio::time::timeout(Duration::from_millis(100), node.recv()).await {
                    Ok(Ok(msg)) => msg,
                    Ok(Err(e)) => {
                        warn!("ADNL recv error: {}", e);
                        continue;
                    }
                    Err(_) => continue, // Timeout, try again
                }
            };

            match message {
                AdnlMessage::Custom { data } => {
                    // Try to parse the TL message
                    if data.len() < 4 {
                        continue;
                    }

                    let schema_id = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);

                    if schema_id == RLDP_MESSAGE_PART {
                        // Parse as RLDP message part
                        let mut reader = TlReader::new(&data);
                        match RldpMessagePart::read_from(&mut reader) {
                            Ok(part) => {
                                trace!(
                                    "Received RLDP message part seqno={} for transfer {}",
                                    part.seqno,
                                    hex::encode(&part.transfer_id[..8])
                                );

                                // Initialize incoming transfer if needed
                                if incoming.is_none() {
                                    incoming = Some(
                                        IncomingTransfer::new(&part)
                                            .map_err(|e| SiteError::RldpError(e.to_string()))?,
                                    );
                                }

                                // Process part
                                if let Some(ref mut transfer) = incoming {
                                    match transfer.process_part(&part) {
                                        Ok(true) => {
                                            // Decoding complete!
                                            let complete = transfer.create_complete(0);
                                            self.send_complete(&complete).await?;

                                            let result = transfer
                                                .take_data(0)
                                                .ok_or_else(|| SiteError::RldpError("No data after decode".to_string()))?;

                                            debug!(
                                                "RLDP transfer {} complete, {} bytes received",
                                                hex::encode(&transfer_id[..8]),
                                                result.len()
                                            );

                                            return Ok(result);
                                        }
                                        Ok(false) => {
                                            // Need more parts
                                            continue;
                                        }
                                        Err(e) => {
                                            warn!("Failed to process RLDP part: {}", e);
                                            continue;
                                        }
                                    }
                                }
                            }
                            Err(e) => {
                                trace!("Failed to parse RLDP message part: {:?}", e);
                            }
                        }
                    } else if schema_id == RLDP_COMPLETE {
                        // Parse as rldp.complete
                        let mut reader = TlReader::new(&data);
                        if let Ok(complete) = RldpComplete::read_from(&mut reader) {
                            if complete.transfer_id == transfer_id {
                                debug!(
                                    "Received rldp.complete for outgoing transfer {}",
                                    hex::encode(&transfer_id[..8])
                                );
                                // Our outgoing transfer was received, continue waiting for response
                            }
                        }
                    }
                }
                AdnlMessage::Query { query_id, query } => {
                    // Server might send us a query (e.g., getNextPayloadPart)
                    trace!("Received ADNL query {}", hex::encode(&query_id[..8]));
                    // For now, we don't handle incoming queries during transfer
                    let _ = query;
                }
                _ => {
                    // Ignore other message types during transfer
                }
            }

            // Send more repair symbols if we have them
            {
                let mut node = self.node.lock().await;
                if let Some(part) = outgoing.next_message_part() {
                    let part_bytes = part.to_bytes();
                    let _ = node.send_custom(&self.peer_id, &part_bytes).await;
                }
            }
        }
    }

    /// Sends rldp.complete message.
    async fn send_complete(&self, complete: &RldpComplete) -> SiteResult<()> {
        let complete_bytes = complete.to_bytes();
        let mut node = self.node.lock().await;
        node.send_custom(&self.peer_id, &complete_bytes)
            .await
            .map_err(|e| SiteError::ConnectionFailed(e.to_string()))?;
        Ok(())
    }

    /// Receives response body via getNextPayloadPart requests.
    async fn get_response_body(&self, request_id: &[u8; 32]) -> SiteResult<Vec<u8>> {
        let mut body = Vec::new();
        let mut seqno = 0;
        let max_size = self.config.max_response_size as usize;

        loop {
            // Create getNextPayloadPart request
            let get_part = GetNextPayloadPart::new(*request_id, seqno, self.config.chunk_size as i32);
            let request_bytes = get_part.to_tl_bytes();

            // Send via RLDP query
            let response = self.rldp_query(&request_bytes).await?;

            // Parse payload part
            let (part, _) = PayloadPart::from_tl_bytes(&response)?;

            // Accumulate data
            body.extend_from_slice(&part.data);

            // Check size limit
            if body.len() > max_size {
                return Err(SiteError::ResponseTooLarge {
                    size: body.len(),
                    max_size,
                });
            }

            // Check if last
            if part.last {
                break;
            }

            seqno += 1;
        }

        Ok(body)
    }
}

impl std::fmt::Debug for UdpRldpTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UdpRldpTransport")
            .field("peers", &self.peers.len())
            .field("config", &self.config)
            .finish()
    }
}

impl std::fmt::Debug for UdpSiteConnection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UdpSiteConnection")
            .field("peer_id", &hex::encode(&self.peer_id[..8]))
            .field("config", &self.config)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_udp_transport_creation() {
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let transport = UdpRldpTransport::bind(addr).await.unwrap();

        let pubkey = transport.public_key().await;
        assert_eq!(pubkey.len(), 32);
    }

    #[test]
    fn test_config_defaults() {
        let config = UdpTransportConfig::default();
        assert_eq!(config.timeout, Duration::from_secs(30));
        assert_eq!(config.max_response_size, 10 * 1024 * 1024);
        assert_eq!(config.chunk_size, 128 * 1024);
    }
}
