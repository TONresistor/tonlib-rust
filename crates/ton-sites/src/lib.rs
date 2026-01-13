//! TON Sites Library
//!
//! This crate provides HTTP over RLDP protocol implementation for accessing
//! TON Sites - decentralized websites hosted on the TON network.
//!
//! # Overview
//!
//! TON Sites are websites accessible via ADNL addresses using the HTTP over RLDP
//! protocol. They enable decentralized web hosting where:
//!
//! - Domains resolve via TON DNS (`.ton` domains)
//! - Direct access via ADNL addresses (`.adnl` domains)
//! - HTTP requests/responses are transported over RLDP protocol
//!
//! # Protocol Flow
//!
//! ```text
//! Client                                              TON Site Server
//!    |                                                       |
//!    |  ────── http.request (via RLDP) ────────────────────> |
//!    |  [id][method][url][headers]                           |
//!    |                                                       |
//!    |  (if request has body)                                |
//!    |  <───── http.getNextPayloadPart ───────────────────── |
//!    |  ────── http.payloadPart ─────────────────────────── >|
//!    |  ...repeat until last=true...                         |
//!    |                                                       |
//!    |  <────── http.response (via RLDP) ─────────────────── |
//!    |  [status_code][headers][no_payload]                   |
//!    |                                                       |
//!    |  (if response has body)                               |
//!    |  ────── http.getNextPayloadPart ─────────────────────>|
//!    |  <───── http.payloadPart ───────────────────────────  |
//!    |  ...repeat until last=true...                         |
//! ```
//!
//! # URL Formats
//!
//! - `http://example.ton/path` - HTTP to a .ton domain
//! - `https://example.ton/path` - HTTPS to a .ton domain
//! - `ton://example.ton/path` - TON-specific scheme
//! - `http://abcd1234...5678.adnl/path` - Direct ADNL address access
//!
//! # Example
//!
//! ```
//! use ton_sites::url::parse_ton_url;
//! use ton_sites::types::{HttpRequest, HttpResponse};
//! use ton_sites::client::{TonSiteClient, MockSiteHandler, MockResponse};
//!
//! // Parse a TON URL
//! let url = parse_ton_url("http://example.ton/index.html").unwrap();
//! assert_eq!(url.domain, "example.ton");
//! assert_eq!(url.path, "/index.html");
//!
//! // Create an HTTP request
//! let request = HttpRequest::get("/index.html")
//!     .with_host("example.ton");
//!
//! // Create a mock client for testing
//! let mut client = TonSiteClient::new_mock();
//!
//! // Add a domain and site
//! let adnl_addr = [0xAB; 32];
//! client.dns_mut().add_domain("example.ton", adnl_addr);
//! client.transport_mut().add_site(
//!     adnl_addr,
//!     MockSiteHandler::new()
//!         .with_route("/index.html", MockResponse::ok("<html>Hello</html>")),
//! );
//!
//! // Make a request
//! let response = client.get("http://example.ton/index.html").unwrap();
//! assert!(response.is_success());
//! ```
//!
//! # TL Message Types
//!
//! This crate implements the following TL message types:
//!
//! | Type | Constructor ID | Description |
//! |------|----------------|-------------|
//! | `http.header` | `0xd5c02ec8` | HTTP header (name-value pair) |
//! | `http.request` | `0x5111e029` | HTTP request |
//! | `http.response` | `0x2c31d138` | HTTP response |
//! | `http.getNextPayloadPart` | `0x0f53f6c4` | Request for next payload chunk |
//! | `http.payloadPart` | `0x1fb5a0e4` | Payload chunk |
//!
//! # Modules
//!
//! - [`error`]: Error types for TON Sites operations
//! - [`types`]: HTTP TL structures (request, response, headers, payload)
//! - [`url`]: URL parsing for .ton and .adnl domains
//! - [`payload`]: Payload streaming for large request/response bodies
//! - [`client`]: TON Site client implementation
//!
//! # References
//!
//! - [TON Sites Documentation](https://docs.ton.org/develop/dapps/tutorials/how-to-run-ton-site)
//! - [HTTP over RLDP](https://github.com/tonutils/tonutils-go/tree/master/adnl/rldp/http)

pub mod client;
pub mod error;
pub mod payload;
pub mod types;
pub mod url;

#[cfg(feature = "lite-client")]
pub mod rldp_transport;

#[cfg(feature = "udp-transport")]
pub mod udp_transport;

// Re-export main types for convenience
pub use client::{
    DnsResolver, MockDnsResolver, MockResponse, MockRldpTransport, MockSiteHandler,
    RldpTransport, RequestBuilder, TonSiteClient, TonSiteClientConfig,
    DEFAULT_MAX_RESPONSE_SIZE, DEFAULT_RLDP_TIMEOUT_MS, DEFAULT_TIMEOUT_MS,
};

// Re-export lite-client types when feature is enabled
#[cfg(feature = "lite-client")]
pub use client::RealTonSiteClient;

#[cfg(feature = "lite-client")]
pub use rldp_transport::{
    RldpTransport as RealRldpTransport, RldpTransportConfig, SiteConnection,
    DEFAULT_MAX_BODY_SIZE, DEFAULT_MAX_RESPONSE_SIZE as RLDP_DEFAULT_MAX_RESPONSE_SIZE,
    DEFAULT_RLDP_TIMEOUT_MS as RLDP_DEFAULT_TIMEOUT_MS,
};

// Re-export UDP transport types when feature is enabled
#[cfg(feature = "udp-transport")]
pub use udp_transport::{
    UdpRldpTransport, UdpSiteConnection, UdpTransportConfig,
};

pub use error::{SiteError, SiteResult};

pub use payload::{
    chunk_count, split_into_chunks, PayloadReceiver, PayloadRequestIterator, PayloadSender,
    DEFAULT_CHUNK_SIZE, MAX_PAYLOAD_SIZE,
};

pub use types::{
    FullHttpResponse, GetNextPayloadPart, HttpHeader, HttpRequest, HttpResponse, PayloadPart,
    TL_HTTP_GET_NEXT_PAYLOAD_PART, TL_HTTP_HEADER, TL_HTTP_PAYLOAD_PART, TL_HTTP_REQUEST,
    TL_HTTP_RESPONSE,
};

pub use url::{
    adnl_to_domain, extract_domain_and_path, format_adnl_address, parse_adnl_address,
    parse_ton_url, TonUrl,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_full_workflow_with_mock() {
        // Create a mock client
        let mut client = TonSiteClient::new_mock();

        // Setup: Add domain and site
        let adnl_addr = [0x12; 32];
        client.dns_mut().add_domain("mysite.ton", adnl_addr);

        let handler = MockSiteHandler::new()
            .with_route("/", MockResponse::ok("<html><body>Welcome to mysite.ton!</body></html>"))
            .with_route("/api/status", MockResponse::ok_with_type(r#"{"status":"online"}"#, "application/json"))
            .with_route("/api/data", MockResponse::ok_with_type(r#"{"data":[1,2,3]}"#, "application/json"));

        client.transport_mut().add_site(adnl_addr, handler);

        // Test: GET request to root
        let response = client.get("http://mysite.ton/").unwrap();
        assert_eq!(response.status_code(), 200);
        assert!(response.is_success());

        // Test: GET request to API endpoint
        let response = client.get("http://mysite.ton/api/status").unwrap();
        assert_eq!(response.status_code(), 200);
        assert_eq!(response.response.content_type(), Some("application/json"));

        // Test: 404 for unknown path
        let response = client.get("http://mysite.ton/unknown").unwrap();
        assert_eq!(response.status_code(), 404);
        assert!(response.response.is_client_error());
    }

    #[test]
    fn test_adnl_direct_access() {
        let mut client = TonSiteClient::new_mock();

        // Setup: Add site with direct ADNL access
        let adnl_addr = [0x34; 32];
        let handler = MockSiteHandler::new()
            .with_route("/", MockResponse::ok("Direct access works!"));
        client.transport_mut().add_site(adnl_addr, handler);

        // Test: Access via .adnl domain
        let adnl_hex = hex::encode(adnl_addr);
        let url = format!("http://{}.adnl/", adnl_hex);
        let response = client.get(&url).unwrap();
        assert_eq!(response.status_code(), 200);
    }

    #[test]
    fn test_url_parsing() {
        // Test .ton URL
        let url = parse_ton_url("http://example.ton/path?query=value#fragment").unwrap();
        assert_eq!(url.scheme, "http");
        assert_eq!(url.domain, "example.ton");
        assert_eq!(url.path, "/path");
        assert_eq!(url.query, Some("query=value".to_string()));
        assert_eq!(url.fragment, Some("fragment".to_string()));
        assert!(url.is_ton_domain());

        // Test .adnl URL
        let adnl_hex = "a".repeat(64);
        let url = parse_ton_url(&format!("http://{}.adnl/", adnl_hex)).unwrap();
        assert!(url.is_adnl_address());
        assert_eq!(url.adnl_address_hex(), Some(adnl_hex.as_str()));
    }

    #[test]
    fn test_http_request_serialization() {
        let request = HttpRequest::get("/test")
            .with_host("example.ton")
            .with_header("Accept", "text/html");

        let bytes = request.to_tl_bytes();
        let (parsed, _) = HttpRequest::from_tl_bytes(&bytes).unwrap();

        assert_eq!(request.id, parsed.id);
        assert_eq!(request.method, parsed.method);
        assert_eq!(request.url, parsed.url);
        assert_eq!(request.headers.len(), parsed.headers.len());
    }

    #[test]
    fn test_http_response_serialization() {
        let response = HttpResponse::ok()
            .with_header("Content-Type", "text/html")
            .with_payload();

        let bytes = response.to_tl_bytes();
        let (parsed, _) = HttpResponse::from_tl_bytes(&bytes).unwrap();

        assert_eq!(response.status_code, parsed.status_code);
        assert_eq!(response.reason, parsed.reason);
        assert_eq!(response.no_payload, parsed.no_payload);
    }

    #[test]
    fn test_payload_streaming() {
        let data: Vec<u8> = (0..500).map(|i| (i % 256) as u8).collect();
        let request_id = [0x56; 32];
        let chunk_size = 100;

        // Sender
        let mut sender = PayloadSender::new(request_id, data.clone());

        // Receiver
        let mut receiver = PayloadReceiver::new(request_id);

        // Transfer
        while !sender.is_complete() {
            let request = receiver.create_request(chunk_size);
            let (part, _) = sender.get_part(request.seqno, request.max_chunk_size).unwrap();
            sender.advance(part.data.len());

            if receiver.add_part(part).unwrap() {
                break;
            }
        }

        assert!(receiver.is_complete());
        assert_eq!(receiver.take_data(), data);
    }

    #[test]
    fn test_request_builder() {
        let (request, url) = RequestBuilder::get("http://example.ton/api")
            .header("Authorization", "Bearer token")
            .content_type("application/json")
            .build()
            .unwrap();

        assert_eq!(request.method, "GET");
        assert_eq!(url.domain, "example.ton");
        assert_eq!(request.url, "/api");
    }

    #[test]
    fn test_error_handling() {
        // Invalid URL
        let result = parse_ton_url("invalid-url");
        assert!(matches!(result.unwrap_err(), SiteError::InvalidUrl(_)));

        // Invalid domain
        let result = parse_ton_url("http://example.com/");
        assert!(matches!(result.unwrap_err(), SiteError::InvalidDomain(_)));

        // Invalid ADNL address
        let result = parse_ton_url("http://abc.adnl/");
        assert!(matches!(result.unwrap_err(), SiteError::InvalidAdnlAddress(_)));
    }

    #[test]
    fn test_full_http_response() {
        let response = HttpResponse::ok()
            .with_header("Content-Type", "text/plain");
        let body = b"Hello, World!".to_vec();
        let full = FullHttpResponse::new(response, body.clone());

        assert_eq!(full.status_code(), 200);
        assert!(full.is_success());
        assert_eq!(full.body, body);
        assert_eq!(full.body_string().unwrap(), "Hello, World!");
    }

    #[test]
    fn test_exports() {
        // Verify main types are exported
        let _ = HttpRequest::get("/");
        let _ = HttpResponse::ok();
        let _ = HttpHeader::new("Test", "Value");
        let _ = PayloadPart::empty_last();
        let _ = GetNextPayloadPart::new([0; 32], 0, 1024);

        // Verify constants are exported
        let _ = DEFAULT_CHUNK_SIZE;
        let _ = MAX_PAYLOAD_SIZE;
        let _ = DEFAULT_MAX_RESPONSE_SIZE;
        let _ = DEFAULT_TIMEOUT_MS;
    }
}
