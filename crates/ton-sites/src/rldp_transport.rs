//! RLDP Transport for TON Sites.
//!
//! This module provides real RLDP transport implementation for connecting to
//! TON Sites over the network, integrating with ton-dns for domain resolution
//! and ton-rldp for reliable data transfer.
//!
//! # Architecture
//!
//! ```text
//! TonSiteClient
//!      |
//!      v
//! RldpTransport
//!      |
//!      +--> TonDns (domain resolution)
//!      |
//!      +--> AdnlNode (ADNL UDP communication)
//!            |
//!            v
//!      RLDP Transfer (FEC-encoded data)
//! ```
//!
//! # Example
//!
//! ```rust,ignore
//! use std::sync::Arc;
//! use ton_sites::rldp_transport::RldpTransport;
//! use ton_dns::TonDns;
//! use ton_adnl::LiteClient;
//!
//! async fn example() -> Result<(), Box<dyn std::error::Error>> {
//!     // Create lite client for DNS resolution
//!     let lite_client = Arc::new(LiteClient::connect("1.2.3.4", 12345, &[0u8; 32]).await?);
//!
//!     // Create DNS resolver
//!     let dns = TonDns::with_lite_client(lite_client.clone());
//!
//!     // Create RLDP transport
//!     let transport = RldpTransport::new(dns);
//!
//!     // Connect to a TON site by domain
//!     let conn = transport.connect_domain("example.ton").await?;
//!
//!     // Make HTTP request
//!     let request = ton_sites::HttpRequest::get("/");
//!     let response = conn.request(request).await?;
//!
//!     Ok(())
//! }
//! ```

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::Mutex;

use ton_dns::{DnsResult, LiteClientBackend, TonDns};
use ton_rldp::{create_query, parse_answer, OutgoingTransfer};

use crate::error::{SiteError, SiteResult};
use crate::payload::{PayloadReceiver, PayloadSender, DEFAULT_CHUNK_SIZE};
use crate::types::{
    FullHttpResponse, GetNextPayloadPart, HttpRequest, HttpResponse, PayloadPart,
};

/// Default maximum response size (10 MB).
pub const DEFAULT_MAX_RESPONSE_SIZE: i64 = 10 * 1024 * 1024;

/// Default RLDP query timeout in milliseconds (30 seconds).
pub const DEFAULT_RLDP_TIMEOUT_MS: i32 = 30_000;

/// Default maximum body size for streaming (10 MB).
pub const DEFAULT_MAX_BODY_SIZE: usize = 10 * 1024 * 1024;

/// RLDP Transport configuration.
#[derive(Debug, Clone)]
pub struct RldpTransportConfig {
    /// Maximum response size in bytes.
    pub max_response_size: i64,
    /// RLDP query timeout in milliseconds.
    pub rldp_timeout_ms: i32,
    /// Chunk size for payload transfers.
    pub chunk_size: usize,
    /// Maximum body size for streaming.
    pub max_body_size: usize,
    /// Connection timeout.
    pub connect_timeout: Duration,
}

impl Default for RldpTransportConfig {
    fn default() -> Self {
        Self {
            max_response_size: DEFAULT_MAX_RESPONSE_SIZE,
            rldp_timeout_ms: DEFAULT_RLDP_TIMEOUT_MS,
            chunk_size: DEFAULT_CHUNK_SIZE,
            max_body_size: DEFAULT_MAX_BODY_SIZE,
            connect_timeout: Duration::from_secs(30),
        }
    }
}

/// RLDP Transport for TON Sites.
///
/// This transport handles connecting to TON Sites by:
/// 1. Resolving .ton domains via TON DNS
/// 2. Establishing ADNL connections to sites
/// 3. Sending HTTP requests via RLDP
/// 4. Receiving HTTP responses and body data
pub struct RldpTransport {
    /// DNS resolver for .ton domains.
    dns: TonDns<LiteClientBackend>,
    /// Transport configuration.
    config: RldpTransportConfig,
}

impl RldpTransport {
    /// Creates a new RLDP transport with the given DNS resolver.
    pub fn new(dns: TonDns<LiteClientBackend>) -> Self {
        Self {
            dns,
            config: RldpTransportConfig::default(),
        }
    }

    /// Creates a new RLDP transport with custom configuration.
    pub fn with_config(dns: TonDns<LiteClientBackend>, config: RldpTransportConfig) -> Self {
        Self { dns, config }
    }

    /// Returns the transport configuration.
    pub fn config(&self) -> &RldpTransportConfig {
        &self.config
    }

    /// Returns a reference to the DNS resolver.
    pub fn dns(&self) -> &TonDns<LiteClientBackend> {
        &self.dns
    }

    /// Resolves a .ton domain to an ADNL address.
    ///
    /// # Arguments
    ///
    /// * `domain` - The .ton domain to resolve (e.g., "example.ton")
    ///
    /// # Returns
    ///
    /// The 32-byte ADNL address for the site.
    pub async fn resolve_domain(&self, domain: &str) -> SiteResult<[u8; 32]> {
        self.dns
            .resolve_site_async(domain)
            .await
            .map_err(|e| SiteError::DnsResolutionFailed(e.to_string()))
    }

    /// Connects to a TON site by ADNL address.
    ///
    /// This creates a connection handle that can be used to make HTTP requests.
    /// Note: In a full implementation, this would establish an ADNL UDP channel.
    /// For now, this creates a connection object that holds the target address.
    ///
    /// # Arguments
    ///
    /// * `adnl_addr` - The 32-byte ADNL address of the site
    ///
    /// # Returns
    ///
    /// A `SiteConnection` for making HTTP requests.
    pub async fn connect(&self, adnl_addr: &[u8; 32]) -> SiteResult<SiteConnection> {
        Ok(SiteConnection::new(*adnl_addr, self.config.clone()))
    }

    /// Resolves a .ton domain and connects to the site.
    ///
    /// This is a convenience method that combines domain resolution with connection.
    ///
    /// # Arguments
    ///
    /// * `domain` - The .ton domain to connect to (e.g., "example.ton")
    ///
    /// # Returns
    ///
    /// A `SiteConnection` for making HTTP requests.
    pub async fn connect_domain(&self, domain: &str) -> SiteResult<SiteConnection> {
        let adnl_addr = self.resolve_domain(domain).await?;
        self.connect(&adnl_addr).await
    }
}

/// A connection to a TON Site.
///
/// Represents an active connection to a TON Site server. Can be used to
/// make HTTP requests and receive responses.
///
/// # Example
///
/// ```rust,ignore
/// let conn = transport.connect_domain("example.ton").await?;
///
/// // Simple GET request
/// let response = conn.get("/index.html").await?;
///
/// // Custom request
/// let request = HttpRequest::post("/api/submit")
///     .with_host("example.ton")
///     .with_content_type("application/json");
/// let response = conn.request(request).await?;
/// ```
pub struct SiteConnection {
    /// The ADNL address of the connected site.
    adnl_addr: [u8; 32],
    /// Connection configuration.
    config: RldpTransportConfig,
    /// Pending requests (for response body streaming).
    pending_requests: Arc<Mutex<std::collections::HashMap<[u8; 32], RequestState>>>,
}

/// State of a pending request.
#[allow(dead_code)]
struct RequestState {
    /// The request ID.
    request_id: [u8; 32],
    /// Body data being sent (for POST/PUT requests).
    body_sender: Option<PayloadSender>,
    /// Body data being received.
    body_receiver: Option<PayloadReceiver>,
}

impl SiteConnection {
    /// Creates a new site connection.
    pub fn new(adnl_addr: [u8; 32], config: RldpTransportConfig) -> Self {
        Self {
            adnl_addr,
            config,
            pending_requests: Arc::new(Mutex::new(std::collections::HashMap::new())),
        }
    }

    /// Returns the ADNL address of the connected site.
    pub fn adnl_addr(&self) -> &[u8; 32] {
        &self.adnl_addr
    }

    /// Makes a GET request.
    ///
    /// # Arguments
    ///
    /// * `path` - The path to request (e.g., "/index.html")
    ///
    /// # Returns
    ///
    /// The full HTTP response including body.
    pub async fn get(&self, path: &str) -> SiteResult<FullHttpResponse> {
        let request = HttpRequest::get(path);
        self.request(request).await
    }

    /// Makes a POST request with body.
    ///
    /// # Arguments
    ///
    /// * `path` - The path to request
    /// * `body` - The request body
    /// * `content_type` - The Content-Type header value
    ///
    /// # Returns
    ///
    /// The full HTTP response including body.
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
    ///
    /// This handles the complete HTTP request/response cycle:
    /// 1. Serialize the request to TL format
    /// 2. Send via RLDP query
    /// 3. Parse the response
    /// 4. Stream response body if present
    ///
    /// # Arguments
    ///
    /// * `request` - The HTTP request to send
    ///
    /// # Returns
    ///
    /// The full HTTP response including body.
    pub async fn request(&self, request: HttpRequest) -> SiteResult<FullHttpResponse> {
        let request_id = request.id;

        // Serialize request to TL
        let request_data = request.to_tl_bytes();

        // Send via RLDP query
        let response_data = self
            .rldp_query(&request_data, self.config.max_response_size, self.config.rldp_timeout_ms)
            .await?;

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

    /// Sends an HTTP request with a body and receives the response.
    ///
    /// This handles requests with body data (POST, PUT, etc.):
    /// 1. Send the request
    /// 2. Handle incoming getNextPayloadPart requests from server
    /// 3. Send body parts
    /// 4. Receive and parse response
    /// 5. Stream response body if present
    ///
    /// # Arguments
    ///
    /// * `request` - The HTTP request to send
    /// * `body` - The request body data
    ///
    /// # Returns
    ///
    /// The full HTTP response including body.
    pub async fn request_with_body(
        &self,
        request: HttpRequest,
        body: Vec<u8>,
    ) -> SiteResult<FullHttpResponse> {
        let request_id = request.id;

        // Create body sender for payload streaming
        let body_sender = PayloadSender::new(request_id, body);

        // Store request state
        {
            let mut pending = self.pending_requests.lock().await;
            pending.insert(
                request_id,
                RequestState {
                    request_id,
                    body_sender: Some(body_sender),
                    body_receiver: None,
                },
            );
        }

        // Serialize request to TL
        let request_data = request.to_tl_bytes();

        // Send request and handle body streaming
        let response_data = self
            .rldp_query_with_body(&request_data, &request_id)
            .await?;

        // Clean up pending request
        {
            let mut pending = self.pending_requests.lock().await;
            pending.remove(&request_id);
        }

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

    /// Sends an RLDP query and waits for response.
    ///
    /// This is the low-level RLDP query mechanism:
    /// 1. Create RLDP query with random query ID
    /// 2. Send via RLDP transfer (FEC-encoded)
    /// 3. Wait for RLDP answer
    ///
    /// # Arguments
    ///
    /// * `data` - The query data to send
    /// * `max_size` - Maximum expected answer size
    /// * `timeout_ms` - Timeout in milliseconds
    ///
    /// # Returns
    ///
    /// The response data.
    async fn rldp_query(&self, data: &[u8], max_size: i64, timeout_ms: i32) -> SiteResult<Vec<u8>> {
        // Create RLDP query
        let (query, query_bytes) = create_query(data, max_size, timeout_ms);

        // In a full implementation, this would:
        // 1. Create an RLDP transfer for the query
        // 2. Send FEC-encoded packets via ADNL UDP
        // 3. Wait for RLDP complete
        // 4. Receive the answer transfer
        // 5. Decode FEC symbols to recover answer
        //
        // For now, we'll simulate the query/answer flow
        let response_bytes = self.send_rldp_transfer(&query_bytes).await?;

        // Parse answer
        let answer = parse_answer(&response_bytes)
            .map_err(|e| SiteError::RldpError(format!("Failed to parse RLDP answer: {}", e)))?;

        // Verify query ID matches
        if answer.query_id != query.query_id {
            return Err(SiteError::RldpError("RLDP query ID mismatch".to_string()));
        }

        Ok(answer.data)
    }

    /// Sends an RLDP query with request body handling.
    ///
    /// This handles the bidirectional communication needed when the request
    /// has a body that needs to be streamed to the server.
    async fn rldp_query_with_body(
        &self,
        data: &[u8],
        request_id: &[u8; 32],
    ) -> SiteResult<Vec<u8>> {
        // Create RLDP query
        let (query, query_bytes) = create_query(
            data,
            self.config.max_response_size,
            self.config.rldp_timeout_ms,
        );

        // Send query and handle body part requests
        // In a full implementation, this would interleave:
        // 1. Sending the query transfer
        // 2. Responding to getNextPayloadPart requests
        // 3. Receiving the response transfer
        let response_bytes = self
            .send_rldp_transfer_with_body_handler(&query_bytes, request_id)
            .await?;

        // Parse answer
        let answer = parse_answer(&response_bytes)
            .map_err(|e| SiteError::RldpError(format!("Failed to parse RLDP answer: {}", e)))?;

        if answer.query_id != query.query_id {
            return Err(SiteError::RldpError("RLDP query ID mismatch".to_string()));
        }

        Ok(answer.data)
    }

    /// Sends an RLDP transfer and receives the response.
    ///
    /// This is a placeholder for the actual RLDP transfer implementation.
    /// In production, this would:
    /// 1. Create OutgoingTransfer with FEC encoding
    /// 2. Send message parts via ADNL UDP
    /// 3. Handle rldp.complete from receiver
    /// 4. Set up IncomingTransfer for answer
    /// 5. Receive and decode answer
    #[allow(unused_variables)]
    async fn send_rldp_transfer(&self, data: &[u8]) -> SiteResult<Vec<u8>> {
        // Create outgoing transfer
        let mut transfer = OutgoingTransfer::new(data);
        let _transfer_id = transfer.transfer_id;

        // Get initial burst of message parts
        let _burst = transfer.initial_burst();

        // In a real implementation:
        // 1. Send each message part via ADNL custom message
        // 2. Continue sending repair symbols
        // 3. Wait for rldp.complete
        // 4. Set up incoming transfer for answer
        // 5. Receive and decode answer

        // For now, return a placeholder error indicating network implementation needed
        Err(SiteError::ConnectionFailed(
            "Real RLDP transport requires ADNL UDP node implementation. \
             Use MockRldpTransport for testing."
                .to_string(),
        ))
    }

    /// Sends an RLDP transfer with body streaming support.
    #[allow(unused_variables)]
    async fn send_rldp_transfer_with_body_handler(
        &self,
        data: &[u8],
        request_id: &[u8; 32],
    ) -> SiteResult<Vec<u8>> {
        // Similar to send_rldp_transfer but also handles incoming
        // getNextPayloadPart requests during the transfer
        Err(SiteError::ConnectionFailed(
            "Real RLDP transport requires ADNL UDP node implementation. \
             Use MockRldpTransport for testing."
                .to_string(),
        ))
    }

    /// Receives the response body by sending getNextPayloadPart requests.
    ///
    /// This streams the response body in chunks:
    /// 1. Send http.getNextPayloadPart request
    /// 2. Receive http.payloadPart response
    /// 3. Repeat until last=true
    ///
    /// # Arguments
    ///
    /// * `request_id` - The request ID to get body for
    ///
    /// # Returns
    ///
    /// The complete response body.
    async fn get_response_body(&self, request_id: &[u8; 32]) -> SiteResult<Vec<u8>> {
        let mut body = Vec::new();
        let mut seqno = 0;

        loop {
            // Create getNextPayloadPart request
            let get_part = GetNextPayloadPart::new(*request_id, seqno, self.config.chunk_size as i32);

            // Send via RLDP query
            let response = self
                .rldp_query(
                    &get_part.to_tl_bytes(),
                    (self.config.chunk_size * 2) as i64,
                    10_000,
                )
                .await?;

            // Parse payload part
            let (part, _) = PayloadPart::from_tl_bytes(&response)?;

            // Accumulate body data
            body.extend_from_slice(&part.data);

            // Check size limit
            if body.len() > self.config.max_body_size {
                return Err(SiteError::ResponseTooLarge {
                    size: body.len(),
                    max_size: self.config.max_body_size,
                });
            }

            // Check if this is the last part
            if part.last {
                break;
            }

            seqno += 1;
        }

        Ok(body)
    }

    /// Handles an incoming getNextPayloadPart request.
    ///
    /// This is called when the server requests the next chunk of a request body.
    ///
    /// # Arguments
    ///
    /// * `request` - The getNextPayloadPart request
    ///
    /// # Returns
    ///
    /// The payloadPart response.
    pub async fn handle_get_next_payload_part(
        &self,
        request: &GetNextPayloadPart,
    ) -> SiteResult<PayloadPart> {
        let mut pending = self.pending_requests.lock().await;

        let state = pending
            .get_mut(&request.id)
            .ok_or_else(|| SiteError::PayloadError("Unknown request ID".to_string()))?;

        let sender = state
            .body_sender
            .as_mut()
            .ok_or_else(|| SiteError::PayloadError("No body sender for request".to_string()))?;

        let part = sender.handle_request(request)?;
        sender.advance(part.data.len());

        Ok(part)
    }
}

impl std::fmt::Debug for SiteConnection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SiteConnection")
            .field("adnl_addr", &hex::encode(self.adnl_addr))
            .field("config", &self.config)
            .finish()
    }
}

/// Async DNS resolver trait extension for TonDns with LiteClientBackend.
///
/// This trait provides async methods that are more efficient when using
/// the LiteClient backend.
pub trait AsyncDnsResolver {
    /// Resolves a .ton domain to its site ADNL address asynchronously.
    fn resolve_site_async(
        &self,
        domain: &str,
    ) -> impl std::future::Future<Output = DnsResult<[u8; 32]>> + Send;
}

impl AsyncDnsResolver for TonDns<LiteClientBackend> {
    async fn resolve_site_async(&self, domain: &str) -> DnsResult<[u8; 32]> {
        // Use the async method from LiteClientBackend
        self.resolve_site_async(domain).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rldp_transport_config_defaults() {
        let config = RldpTransportConfig::default();

        assert_eq!(config.max_response_size, DEFAULT_MAX_RESPONSE_SIZE);
        assert_eq!(config.rldp_timeout_ms, DEFAULT_RLDP_TIMEOUT_MS);
        assert_eq!(config.chunk_size, DEFAULT_CHUNK_SIZE);
        assert_eq!(config.max_body_size, DEFAULT_MAX_BODY_SIZE);
    }

    #[test]
    fn test_site_connection_creation() {
        let adnl_addr = [0xAB; 32];
        let config = RldpTransportConfig::default();
        let conn = SiteConnection::new(adnl_addr, config);

        assert_eq!(conn.adnl_addr(), &adnl_addr);
    }

    #[test]
    fn test_site_connection_debug() {
        let adnl_addr = [0xAB; 32];
        let config = RldpTransportConfig::default();
        let conn = SiteConnection::new(adnl_addr, config);

        let debug_str = format!("{:?}", conn);
        assert!(debug_str.contains("SiteConnection"));
        assert!(debug_str.contains("abababab")); // hex-encoded
    }

    #[tokio::test]
    async fn test_site_connection_request_needs_network() {
        let adnl_addr = [0xAB; 32];
        let config = RldpTransportConfig::default();
        let conn = SiteConnection::new(adnl_addr, config);

        // Attempting to make a request should fail since we don't have
        // a real ADNL UDP implementation
        let request = HttpRequest::get("/");
        let result = conn.request(request).await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), SiteError::ConnectionFailed(_)));
    }

    #[test]
    fn test_request_state() {
        let request_id = [0x12; 32];
        let body = b"test body".to_vec();
        let sender = PayloadSender::new(request_id, body);

        let state = RequestState {
            request_id,
            body_sender: Some(sender),
            body_receiver: None,
        };

        assert_eq!(state.request_id, request_id);
        assert!(state.body_sender.is_some());
        assert!(state.body_receiver.is_none());
    }
}
