//! TON Site client implementation.
//!
//! This module provides the `TonSiteClient` for making HTTP requests to TON Sites
//! via the RLDP protocol.
//!
//! # Overview
//!
//! TON Sites are decentralized websites accessible via ADNL addresses. They can be
//! accessed either by their .ton domain (resolved via TON DNS) or directly by their
//! .adnl address.
//!
//! # Example (Mock)
//!
//! ```
//! use ton_sites::client::{TonSiteClient, TonSiteClientConfig, MockSiteHandler, MockResponse};
//!
//! // Create a client with mock backend for testing
//! let mut client = TonSiteClient::new_mock();
//!
//! // Configure mock
//! let adnl_addr = [0xAB; 32];
//! client.dns_mut().add_domain("example.ton", adnl_addr);
//! client.transport_mut().add_site(adnl_addr, MockSiteHandler::new()
//!     .with_route("/", MockResponse::ok("Hello!")));
//!
//! // Make a GET request
//! let response = client.get("http://example.ton/").unwrap();
//! assert!(response.is_success());
//! ```
//!
//! # Example (Real Network)
//!
//! ```ignore
//! use std::sync::Arc;
//! use ton_sites::client::TonSiteClient;
//! use ton_dns::{TonDns, LiteClientBackend};
//! use ton_adnl::LiteClient;
//!
//! async fn example() -> Result<(), Box<dyn std::error::Error>> {
//!     // Connect to a liteserver
//!     let lite_client = Arc::new(LiteClient::connect(
//!         "1.2.3.4:12345".parse()?,
//!         &server_pubkey,
//!     ).await?);
//!
//!     // Create client with real DNS backend
//!     let client = TonSiteClient::with_lite_client(lite_client).await?;
//!
//!     // Make a GET request
//!     let response = client.get_async("http://foundation.ton/").await?;
//!     println!("Status: {}", response.status_code());
//!
//!     Ok(())
//! }
//! ```

use crate::error::{SiteError, SiteResult};
use crate::payload::DEFAULT_CHUNK_SIZE;
use crate::types::{FullHttpResponse, HttpHeader, HttpRequest, HttpResponse};
use crate::url::{parse_ton_url, TonUrl};

/// Default maximum response size (10 MB).
pub const DEFAULT_MAX_RESPONSE_SIZE: usize = 10 * 1024 * 1024;

/// Default request timeout in milliseconds (30 seconds).
pub const DEFAULT_TIMEOUT_MS: u64 = 30_000;

/// Default RLDP query timeout in milliseconds.
pub const DEFAULT_RLDP_TIMEOUT_MS: u64 = 30_000;

/// Configuration for `TonSiteClient`.
#[derive(Debug, Clone)]
pub struct TonSiteClientConfig {
    /// Maximum response size in bytes.
    pub max_response_size: usize,
    /// Request timeout in milliseconds.
    pub timeout_ms: u64,
    /// RLDP query timeout in milliseconds.
    pub rldp_timeout_ms: u64,
    /// Chunk size for payload transfers.
    pub chunk_size: usize,
}

impl Default for TonSiteClientConfig {
    fn default() -> Self {
        Self {
            max_response_size: DEFAULT_MAX_RESPONSE_SIZE,
            timeout_ms: DEFAULT_TIMEOUT_MS,
            rldp_timeout_ms: DEFAULT_RLDP_TIMEOUT_MS,
            chunk_size: DEFAULT_CHUNK_SIZE,
        }
    }
}

impl TonSiteClientConfig {
    /// Create a new configuration with default values.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the maximum response size.
    pub fn with_max_response_size(mut self, size: usize) -> Self {
        self.max_response_size = size;
        self
    }

    /// Set the request timeout.
    pub fn with_timeout_ms(mut self, timeout_ms: u64) -> Self {
        self.timeout_ms = timeout_ms;
        self
    }

    /// Set the RLDP query timeout.
    pub fn with_rldp_timeout_ms(mut self, timeout_ms: u64) -> Self {
        self.rldp_timeout_ms = timeout_ms;
        self
    }

    /// Set the chunk size for payload transfers.
    pub fn with_chunk_size(mut self, chunk_size: usize) -> Self {
        self.chunk_size = chunk_size;
        self
    }
}

/// A trait for DNS resolution backends.
///
/// This allows the client to work with different DNS implementations,
/// including mock implementations for testing.
pub trait DnsResolver {
    /// Resolve a .ton domain to an ADNL address.
    fn resolve_site(&self, domain: &str) -> SiteResult<[u8; 32]>;
}

/// A trait for RLDP transport backends.
///
/// This allows the client to work with different RLDP implementations,
/// including mock implementations for testing.
pub trait RldpTransport {
    /// Send an RLDP query and receive a response.
    fn query(
        &self,
        adnl_address: &[u8; 32],
        data: &[u8],
        max_answer_size: usize,
        timeout_ms: u64,
    ) -> SiteResult<Vec<u8>>;
}

/// A mock DNS resolver for testing.
#[derive(Debug, Default)]
pub struct MockDnsResolver {
    /// Mapping of domain to ADNL address.
    domains: std::collections::HashMap<String, [u8; 32]>,
}

impl MockDnsResolver {
    /// Create a new mock DNS resolver.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a domain mapping.
    pub fn add_domain(&mut self, domain: &str, adnl_address: [u8; 32]) {
        self.domains.insert(domain.to_lowercase(), adnl_address);
    }
}

impl DnsResolver for MockDnsResolver {
    fn resolve_site(&self, domain: &str) -> SiteResult<[u8; 32]> {
        self.domains
            .get(&domain.to_lowercase())
            .copied()
            .ok_or_else(|| SiteError::DnsResolutionFailed(format!("domain not found: {}", domain)))
    }
}

/// A mock RLDP transport for testing.
#[derive(Debug, Default)]
pub struct MockRldpTransport {
    /// Response handler: (request bytes) -> response bytes
    responses: std::collections::HashMap<[u8; 32], MockSiteHandler>,
}

/// Handler for a mock site.
#[derive(Debug, Clone)]
pub struct MockSiteHandler {
    /// Routes mapping path to response.
    routes: std::collections::HashMap<String, MockResponse>,
    /// Default response for unknown paths.
    default_response: MockResponse,
}

/// A mock HTTP response.
#[derive(Debug, Clone)]
pub struct MockResponse {
    /// Status code.
    pub status_code: i32,
    /// Response body.
    pub body: Vec<u8>,
    /// Content type.
    pub content_type: String,
}

impl Default for MockResponse {
    fn default() -> Self {
        Self {
            status_code: 404,
            body: b"Not Found".to_vec(),
            content_type: "text/plain".to_string(),
        }
    }
}

impl MockResponse {
    /// Create a 200 OK response with the given body.
    pub fn ok(body: impl Into<Vec<u8>>) -> Self {
        Self {
            status_code: 200,
            body: body.into(),
            content_type: "text/html".to_string(),
        }
    }

    /// Create a 200 OK response with the given body and content type.
    pub fn ok_with_type(body: impl Into<Vec<u8>>, content_type: &str) -> Self {
        Self {
            status_code: 200,
            body: body.into(),
            content_type: content_type.to_string(),
        }
    }

    /// Create a 404 Not Found response.
    pub fn not_found() -> Self {
        Self::default()
    }

    /// Create a redirect response.
    pub fn redirect(status_code: i32, _location: &str) -> Self {
        // Note: In a full implementation, location would be added as a header
        Self {
            status_code,
            body: Vec::new(),
            content_type: "text/plain".to_string(),
        }
    }
}

impl Default for MockSiteHandler {
    fn default() -> Self {
        Self {
            routes: std::collections::HashMap::new(),
            default_response: MockResponse::not_found(),
        }
    }
}

impl MockSiteHandler {
    /// Create a new mock site handler.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a route.
    pub fn with_route(mut self, path: &str, response: MockResponse) -> Self {
        self.routes.insert(path.to_string(), response);
        self
    }

    /// Set the default response.
    pub fn with_default(mut self, response: MockResponse) -> Self {
        self.default_response = response;
        self
    }

    /// Get the response for a path.
    pub fn get_response(&self, path: &str) -> &MockResponse {
        self.routes.get(path).unwrap_or(&self.default_response)
    }
}

impl MockRldpTransport {
    /// Create a new mock RLDP transport.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a site handler.
    pub fn add_site(&mut self, adnl_address: [u8; 32], handler: MockSiteHandler) {
        self.responses.insert(adnl_address, handler);
    }

    /// Handle a request and generate a mock response.
    fn handle_request(&self, adnl_address: &[u8; 32], request: &HttpRequest) -> SiteResult<Vec<u8>> {
        let handler = self
            .responses
            .get(adnl_address)
            .ok_or_else(|| SiteError::ConnectionFailed("site not found".to_string()))?;

        let mock_response = handler.get_response(&request.url);

        let has_body = !mock_response.body.is_empty();
        let response = HttpResponse::new(mock_response.status_code, reason_for_status(mock_response.status_code))
            .with_header("Content-Type", &mock_response.content_type);

        let response = if has_body {
            response
                .with_header("Content-Length", mock_response.body.len().to_string())
                .with_payload()
        } else {
            response
        };

        Ok(response.to_tl_bytes())
    }
}

impl RldpTransport for MockRldpTransport {
    fn query(
        &self,
        adnl_address: &[u8; 32],
        data: &[u8],
        _max_answer_size: usize,
        _timeout_ms: u64,
    ) -> SiteResult<Vec<u8>> {
        // Parse the request
        let (request, _) = HttpRequest::from_tl_bytes(data)?;
        self.handle_request(adnl_address, &request)
    }
}

/// Get the reason phrase for a status code.
fn reason_for_status(status_code: i32) -> &'static str {
    match status_code {
        200 => "OK",
        201 => "Created",
        204 => "No Content",
        301 => "Moved Permanently",
        302 => "Found",
        304 => "Not Modified",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        500 => "Internal Server Error",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        _ => "Unknown",
    }
}

/// TON Site client for making HTTP requests via RLDP.
pub struct TonSiteClient<D: DnsResolver, T: RldpTransport> {
    /// DNS resolver.
    dns: D,
    /// RLDP transport.
    transport: T,
    /// Client configuration.
    config: TonSiteClientConfig,
}

impl TonSiteClient<MockDnsResolver, MockRldpTransport> {
    /// Create a new client with mock backends for testing.
    pub fn new_mock() -> Self {
        Self {
            dns: MockDnsResolver::new(),
            transport: MockRldpTransport::new(),
            config: TonSiteClientConfig::default(),
        }
    }

    /// Get a mutable reference to the mock DNS resolver.
    pub fn dns_mut(&mut self) -> &mut MockDnsResolver {
        &mut self.dns
    }

    /// Get a mutable reference to the mock RLDP transport.
    pub fn transport_mut(&mut self) -> &mut MockRldpTransport {
        &mut self.transport
    }
}

impl<D: DnsResolver, T: RldpTransport> TonSiteClient<D, T> {
    /// Create a new client with custom backends.
    pub fn new(dns: D, transport: T) -> Self {
        Self {
            dns,
            transport,
            config: TonSiteClientConfig::default(),
        }
    }

    /// Create a new client with custom backends and configuration.
    pub fn with_config(dns: D, transport: T, config: TonSiteClientConfig) -> Self {
        Self { dns, transport, config }
    }

    /// Get the client configuration.
    pub fn config(&self) -> &TonSiteClientConfig {
        &self.config
    }

    /// Make an HTTP request.
    ///
    /// This is the main method for making requests to TON Sites.
    pub fn request(&self, request: HttpRequest, url: &TonUrl) -> SiteResult<FullHttpResponse> {
        // Resolve ADNL address
        let adnl_address = self.resolve_adnl_address(url)?;

        // Send request via RLDP
        let response_data = self.transport.query(
            &adnl_address,
            &request.to_tl_bytes(),
            self.config.max_response_size,
            self.config.rldp_timeout_ms,
        )?;

        // Parse response
        let (response, _) = HttpResponse::from_tl_bytes(&response_data)?;

        // Get body if present
        let body = if !response.no_payload {
            // In a real implementation, this would use payload streaming
            // For now, return an empty body for mock testing
            Vec::new()
        } else {
            Vec::new()
        };

        Ok(FullHttpResponse::new(response, body))
    }

    /// Make a GET request.
    pub fn get(&self, url: &str) -> SiteResult<FullHttpResponse> {
        let parsed_url = parse_ton_url(url)?;
        let request = HttpRequest::get(parsed_url.full_path())
            .with_host(parsed_url.host());

        self.request(request, &parsed_url)
    }

    /// Make a POST request.
    pub fn post(&self, url: &str, body: Vec<u8>, content_type: &str) -> SiteResult<FullHttpResponse> {
        let parsed_url = parse_ton_url(url)?;
        let request = HttpRequest::post(parsed_url.full_path())
            .with_host(parsed_url.host())
            .with_content_type(content_type)
            .with_content_length(body.len());

        self.request(request, &parsed_url)
    }

    /// Make a PUT request.
    pub fn put(&self, url: &str, body: Vec<u8>, content_type: &str) -> SiteResult<FullHttpResponse> {
        let parsed_url = parse_ton_url(url)?;
        let request = HttpRequest::new("PUT", parsed_url.full_path())
            .with_host(parsed_url.host())
            .with_content_type(content_type)
            .with_content_length(body.len());

        self.request(request, &parsed_url)
    }

    /// Make a DELETE request.
    pub fn delete(&self, url: &str) -> SiteResult<FullHttpResponse> {
        let parsed_url = parse_ton_url(url)?;
        let request = HttpRequest::new("DELETE", parsed_url.full_path())
            .with_host(parsed_url.host());

        self.request(request, &parsed_url)
    }

    /// Make a HEAD request.
    pub fn head(&self, url: &str) -> SiteResult<FullHttpResponse> {
        let parsed_url = parse_ton_url(url)?;
        let request = HttpRequest::new("HEAD", parsed_url.full_path())
            .with_host(parsed_url.host());

        self.request(request, &parsed_url)
    }

    /// Resolve a URL to an ADNL address.
    fn resolve_adnl_address(&self, url: &TonUrl) -> SiteResult<[u8; 32]> {
        if url.is_adnl_address() {
            // Direct ADNL address
            url.parse_adnl_address()
        } else if url.is_ton_domain() {
            // Resolve via DNS
            self.dns.resolve_site(&url.domain)
        } else {
            Err(SiteError::InvalidDomain(url.domain.clone()))
        }
    }
}

/// Builder for HTTP requests to TON Sites.
#[derive(Debug, Clone)]
pub struct RequestBuilder {
    method: String,
    url: String,
    headers: Vec<HttpHeader>,
    body: Option<Vec<u8>>,
}

impl RequestBuilder {
    /// Create a new request builder.
    pub fn new(method: &str, url: &str) -> Self {
        Self {
            method: method.to_string(),
            url: url.to_string(),
            headers: Vec::new(),
            body: None,
        }
    }

    /// Create a GET request builder.
    pub fn get(url: &str) -> Self {
        Self::new("GET", url)
    }

    /// Create a POST request builder.
    pub fn post(url: &str) -> Self {
        Self::new("POST", url)
    }

    /// Add a header.
    pub fn header(mut self, name: &str, value: &str) -> Self {
        self.headers.push(HttpHeader::new(name, value));
        self
    }

    /// Set the request body.
    pub fn body(mut self, body: Vec<u8>) -> Self {
        self.body = Some(body);
        self
    }

    /// Set the Content-Type header.
    pub fn content_type(self, content_type: &str) -> Self {
        self.header("Content-Type", content_type)
    }

    /// Build the HTTP request.
    pub fn build(self) -> SiteResult<(HttpRequest, TonUrl)> {
        let url = parse_ton_url(&self.url)?;

        let mut request = HttpRequest::new(&self.method, url.full_path())
            .with_host(url.host());

        for header in self.headers {
            request = request.with_header(header.name, header.value);
        }

        if let Some(body) = &self.body {
            request = request.with_content_length(body.len());
        }

        Ok((request, url))
    }
}

// ============================================================================
// Real RLDP Transport Client (requires lite-client feature)
// ============================================================================

#[cfg(feature = "lite-client")]
pub use lite_client_impl::*;

#[cfg(feature = "lite-client")]
mod lite_client_impl {
    use super::*;
    use std::sync::Arc;
    use ton_adnl::LiteClient;
    use ton_dns::TonDns;
    use crate::rldp_transport::{RldpTransport, RldpTransportConfig, SiteConnection};

    /// TON Site client with real RLDP transport.
    ///
    /// This client uses the LiteClient backend for DNS resolution and
    /// RLDP for HTTP communication with TON Sites.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use std::sync::Arc;
    /// use ton_sites::RealTonSiteClient;
    /// use ton_adnl::LiteClient;
    ///
    /// async fn example() -> Result<(), Box<dyn std::error::Error>> {
    ///     // Connect to a liteserver
    ///     let lite_client = Arc::new(LiteClient::connect("1.2.3.4", 12345, &[0u8; 32]).await?);
    ///
    ///     // Create TON Site client
    ///     let client = RealTonSiteClient::new(lite_client);
    ///
    ///     // Resolve a domain
    ///     let adnl_addr = client.resolve_domain("foundation.ton").await?;
    ///
    ///     // Connect to a site
    ///     let conn = client.connect(&adnl_addr).await?;
    ///
    ///     // Make a request
    ///     let response = conn.get("/").await?;
    ///
    ///     Ok(())
    /// }
    /// ```
    pub struct RealTonSiteClient {
        /// RLDP transport.
        transport: RldpTransport,
        /// Client configuration.
        config: TonSiteClientConfig,
    }

    impl RealTonSiteClient {
        /// Creates a new client with the given LiteClient.
        ///
        /// # Arguments
        ///
        /// * `lite_client` - The LiteClient for DNS resolution
        pub fn new(lite_client: Arc<LiteClient>) -> Self {
            let dns = TonDns::with_lite_client(lite_client);
            let transport = RldpTransport::new(dns);
            Self {
                transport,
                config: TonSiteClientConfig::default(),
            }
        }

        /// Creates a new client with custom configuration.
        pub fn with_config(lite_client: Arc<LiteClient>, config: TonSiteClientConfig) -> Self {
            let dns = TonDns::with_lite_client(lite_client);
            let rldp_config = RldpTransportConfig {
                max_response_size: config.max_response_size as i64,
                rldp_timeout_ms: config.rldp_timeout_ms as i32,
                chunk_size: config.chunk_size,
                max_body_size: config.max_response_size,
                connect_timeout: std::time::Duration::from_millis(config.timeout_ms),
            };
            let transport = RldpTransport::with_config(dns, rldp_config);
            Self { transport, config }
        }

        /// Returns the client configuration.
        pub fn config(&self) -> &TonSiteClientConfig {
            &self.config
        }

        /// Returns a reference to the transport.
        pub fn transport(&self) -> &RldpTransport {
            &self.transport
        }

        /// Resolves a .ton domain to an ADNL address.
        ///
        /// # Arguments
        ///
        /// * `domain` - The .ton domain (e.g., "foundation.ton")
        ///
        /// # Returns
        ///
        /// The 32-byte ADNL address.
        pub async fn resolve_domain(&self, domain: &str) -> SiteResult<[u8; 32]> {
            self.transport.resolve_domain(domain).await
        }

        /// Connects to a TON site by ADNL address.
        ///
        /// # Arguments
        ///
        /// * `adnl_addr` - The 32-byte ADNL address
        ///
        /// # Returns
        ///
        /// A `SiteConnection` for making HTTP requests.
        pub async fn connect(&self, adnl_addr: &[u8; 32]) -> SiteResult<SiteConnection> {
            self.transport.connect(adnl_addr).await
        }

        /// Resolves a domain and connects to the site.
        ///
        /// # Arguments
        ///
        /// * `domain` - The .ton domain (e.g., "foundation.ton")
        ///
        /// # Returns
        ///
        /// A `SiteConnection` for making HTTP requests.
        pub async fn connect_domain(&self, domain: &str) -> SiteResult<SiteConnection> {
            self.transport.connect_domain(domain).await
        }

        /// Makes an async GET request to a URL.
        ///
        /// # Arguments
        ///
        /// * `url` - The URL to request (e.g., "http://foundation.ton/")
        ///
        /// # Returns
        ///
        /// The full HTTP response including body.
        pub async fn get_async(&self, url: &str) -> SiteResult<FullHttpResponse> {
            let parsed_url = parse_ton_url(url)?;
            let conn = if parsed_url.is_adnl_address() {
                let adnl_addr = parsed_url.parse_adnl_address()?;
                self.connect(&adnl_addr).await?
            } else {
                self.connect_domain(&parsed_url.domain).await?
            };

            let request = HttpRequest::get(parsed_url.full_path())
                .with_host(parsed_url.host());

            conn.request(request).await
        }

        /// Makes an async POST request to a URL.
        ///
        /// # Arguments
        ///
        /// * `url` - The URL to request
        /// * `body` - The request body
        /// * `content_type` - The Content-Type header value
        ///
        /// # Returns
        ///
        /// The full HTTP response including body.
        pub async fn post_async(
            &self,
            url: &str,
            body: Vec<u8>,
            content_type: &str,
        ) -> SiteResult<FullHttpResponse> {
            let parsed_url = parse_ton_url(url)?;
            let conn = if parsed_url.is_adnl_address() {
                let adnl_addr = parsed_url.parse_adnl_address()?;
                self.connect(&adnl_addr).await?
            } else {
                self.connect_domain(&parsed_url.domain).await?
            };

            conn.post(&parsed_url.full_path(), body, content_type).await
        }

        /// Makes a custom async request.
        ///
        /// # Arguments
        ///
        /// * `url` - The URL to request
        /// * `request` - The HTTP request
        ///
        /// # Returns
        ///
        /// The full HTTP response including body.
        pub async fn request_async(&self, url: &str, request: HttpRequest) -> SiteResult<FullHttpResponse> {
            let parsed_url = parse_ton_url(url)?;
            let conn = if parsed_url.is_adnl_address() {
                let adnl_addr = parsed_url.parse_adnl_address()?;
                self.connect(&adnl_addr).await?
            } else {
                self.connect_domain(&parsed_url.domain).await?
            };

            conn.request(request).await
        }

        /// Makes a custom async request with body.
        ///
        /// # Arguments
        ///
        /// * `url` - The URL to request
        /// * `request` - The HTTP request
        /// * `body` - The request body
        ///
        /// # Returns
        ///
        /// The full HTTP response including body.
        pub async fn request_with_body_async(
            &self,
            url: &str,
            request: HttpRequest,
            body: Vec<u8>,
        ) -> SiteResult<FullHttpResponse> {
            let parsed_url = parse_ton_url(url)?;
            let conn = if parsed_url.is_adnl_address() {
                let adnl_addr = parsed_url.parse_adnl_address()?;
                self.connect(&adnl_addr).await?
            } else {
                self.connect_domain(&parsed_url.domain).await?
            };

            conn.request_with_body(request, body).await
        }
    }

    impl std::fmt::Debug for RealTonSiteClient {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("RealTonSiteClient")
                .field("config", &self.config)
                .finish()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mock_client_get() {
        let mut client = TonSiteClient::new_mock();

        // Add a domain
        let adnl_addr = [0xAB; 32];
        client.dns_mut().add_domain("example.ton", adnl_addr);

        // Add a site handler
        let handler = MockSiteHandler::new()
            .with_route("/", MockResponse::ok("<html>Hello</html>"))
            .with_route("/api", MockResponse::ok_with_type(r#"{"status":"ok"}"#, "application/json"));
        client.transport_mut().add_site(adnl_addr, handler);

        // Make a request
        let response = client.get("http://example.ton/").unwrap();
        assert_eq!(response.status_code(), 200);
        assert!(response.is_success());
    }

    #[test]
    fn test_mock_client_404() {
        let mut client = TonSiteClient::new_mock();

        let adnl_addr = [0xAB; 32];
        client.dns_mut().add_domain("example.ton", adnl_addr);
        client.transport_mut().add_site(adnl_addr, MockSiteHandler::new());

        let response = client.get("http://example.ton/missing").unwrap();
        assert_eq!(response.status_code(), 404);
        assert!(response.response.is_client_error());
    }

    #[test]
    fn test_mock_client_dns_not_found() {
        let client = TonSiteClient::new_mock();

        let result = client.get("http://unknown.ton/");
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), SiteError::DnsResolutionFailed(_)));
    }

    #[test]
    fn test_mock_client_adnl_address() {
        let mut client = TonSiteClient::new_mock();

        let adnl_addr = [0xCD; 32];
        let handler = MockSiteHandler::new()
            .with_route("/", MockResponse::ok("Direct access"));
        client.transport_mut().add_site(adnl_addr, handler);

        let adnl_hex = hex::encode(adnl_addr);
        let url = format!("http://{}.adnl/", adnl_hex);
        let response = client.get(&url).unwrap();
        assert_eq!(response.status_code(), 200);
    }

    #[test]
    fn test_request_builder() {
        let (request, url) = RequestBuilder::get("http://example.ton/api")
            .header("Accept", "application/json")
            .header("Authorization", "Bearer token")
            .build()
            .unwrap();

        assert_eq!(request.method, "GET");
        assert_eq!(request.url, "/api");
        assert_eq!(url.domain, "example.ton");
        assert!(request.headers.iter().any(|h| h.name == "Accept"));
        assert!(request.headers.iter().any(|h| h.name == "Authorization"));
    }

    #[test]
    fn test_request_builder_with_body() {
        let body = b"test body".to_vec();
        let (request, _) = RequestBuilder::post("http://example.ton/submit")
            .content_type("text/plain")
            .body(body.clone())
            .build()
            .unwrap();

        assert_eq!(request.method, "POST");
        assert!(request.headers.iter().any(|h| h.name == "Content-Type" && h.value == "text/plain"));
        assert!(request.headers.iter().any(|h| h.name == "Content-Length"));
    }

    #[test]
    fn test_config() {
        let config = TonSiteClientConfig::new()
            .with_max_response_size(5 * 1024 * 1024)
            .with_timeout_ms(60_000)
            .with_rldp_timeout_ms(45_000)
            .with_chunk_size(64 * 1024);

        assert_eq!(config.max_response_size, 5 * 1024 * 1024);
        assert_eq!(config.timeout_ms, 60_000);
        assert_eq!(config.rldp_timeout_ms, 45_000);
        assert_eq!(config.chunk_size, 64 * 1024);
    }

    #[test]
    fn test_mock_response_types() {
        let ok = MockResponse::ok("body");
        assert_eq!(ok.status_code, 200);
        assert_eq!(ok.body, b"body".to_vec());

        let json = MockResponse::ok_with_type(r#"{"a":1}"#, "application/json");
        assert_eq!(json.content_type, "application/json");

        let not_found = MockResponse::not_found();
        assert_eq!(not_found.status_code, 404);
    }

    #[test]
    fn test_mock_site_handler() {
        let handler = MockSiteHandler::new()
            .with_route("/", MockResponse::ok("home"))
            .with_route("/about", MockResponse::ok("about"))
            .with_default(MockResponse::not_found());

        assert_eq!(handler.get_response("/").status_code, 200);
        assert_eq!(handler.get_response("/about").status_code, 200);
        assert_eq!(handler.get_response("/unknown").status_code, 404);
    }

    #[test]
    fn test_reason_for_status() {
        assert_eq!(reason_for_status(200), "OK");
        assert_eq!(reason_for_status(404), "Not Found");
        assert_eq!(reason_for_status(500), "Internal Server Error");
        assert_eq!(reason_for_status(999), "Unknown");
    }
}
