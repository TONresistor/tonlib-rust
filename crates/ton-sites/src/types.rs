//! HTTP over RLDP TL structures.
//!
//! This module defines the TL structures used for HTTP communication over RLDP protocol
//! as specified in the TON documentation.
//!
//! # TL Schema
//!
//! ```tl
//! http.header name:string value:string = http.Header;
//! http.request id:int256 method:string url:string http_version:string
//!              headers:(vector http.header) = http.Response;
//! http.response http_version:string status_code:int reason:string
//!               headers:(vector http.header) no_payload:Bool = http.Response;
//! http.getNextPayloadPart id:int256 seqno:int max_chunk_size:int = http.PayloadPart;
//! http.payloadPart data:bytes trailer:(vector http.header) last:Bool = http.PayloadPart;
//! ```

use crate::error::{SiteError, SiteResult};

/// TL constructor ID for http.header
pub const TL_HTTP_HEADER: u32 = 0xd5c02ec8;

/// TL constructor ID for http.request
/// OFFICIAL TON ID - documented in RLDP protocol specification
pub const TL_HTTP_REQUEST: u32 = 0xe191b161;

/// TL constructor ID for http.response
pub const TL_HTTP_RESPONSE: u32 = 0x2c31d138;

/// TL constructor ID for http.getNextPayloadPart
pub const TL_HTTP_GET_NEXT_PAYLOAD_PART: u32 = 0x0f53f6c4;

/// TL constructor ID for http.payloadPart
pub const TL_HTTP_PAYLOAD_PART: u32 = 0x1fb5a0e4;

/// An HTTP header (name-value pair).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpHeader {
    /// Header name (e.g., "Content-Type").
    pub name: String,
    /// Header value (e.g., "text/html").
    pub value: String,
}

impl HttpHeader {
    /// Create a new HTTP header.
    pub fn new(name: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            value: value.into(),
        }
    }

    /// Serialize to TL bytes.
    pub fn to_tl_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&TL_HTTP_HEADER.to_le_bytes());
        write_tl_string(&mut buf, &self.name);
        write_tl_string(&mut buf, &self.value);
        buf
    }

    /// Deserialize from TL bytes.
    pub fn from_tl_bytes(data: &[u8]) -> SiteResult<(Self, usize)> {
        if data.len() < 4 {
            return Err(SiteError::SerializationError("data too short".to_string()));
        }

        let id = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        if id != TL_HTTP_HEADER {
            return Err(SiteError::SerializationError(format!(
                "unexpected TL ID: 0x{:08x}, expected http.header",
                id
            )));
        }

        let mut offset = 4;
        let (name, consumed) = read_tl_string(&data[offset..])?;
        offset += consumed;
        let (value, consumed) = read_tl_string(&data[offset..])?;
        offset += consumed;

        Ok((Self { name, value }, offset))
    }
}

/// An HTTP request sent over RLDP.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpRequest {
    /// Unique request ID (256-bit).
    pub id: [u8; 32],
    /// HTTP method (GET, POST, etc.).
    pub method: String,
    /// Request URL (path portion).
    pub url: String,
    /// HTTP version string (e.g., "HTTP/1.1").
    pub http_version: String,
    /// Request headers.
    pub headers: Vec<HttpHeader>,
}

impl HttpRequest {
    /// Create a new HTTP request with a random ID.
    pub fn new(method: impl Into<String>, url: impl Into<String>) -> Self {
        let mut id = [0u8; 32];
        getrandom(&mut id);
        Self {
            id,
            method: method.into(),
            url: url.into(),
            http_version: "HTTP/1.1".to_string(),
            headers: Vec::new(),
        }
    }

    /// Create a GET request.
    pub fn get(url: impl Into<String>) -> Self {
        Self::new("GET", url)
    }

    /// Create a POST request.
    pub fn post(url: impl Into<String>) -> Self {
        Self::new("POST", url)
    }

    /// Add a header to the request.
    pub fn with_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.push(HttpHeader::new(name, value));
        self
    }

    /// Set the Host header.
    pub fn with_host(self, host: impl Into<String>) -> Self {
        self.with_header("Host", host)
    }

    /// Set the Content-Type header.
    pub fn with_content_type(self, content_type: impl Into<String>) -> Self {
        self.with_header("Content-Type", content_type)
    }

    /// Set the Content-Length header.
    pub fn with_content_length(self, length: usize) -> Self {
        self.with_header("Content-Length", length.to_string())
    }

    /// Serialize to TL bytes.
    pub fn to_tl_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&TL_HTTP_REQUEST.to_le_bytes());
        buf.extend_from_slice(&self.id);
        write_tl_string(&mut buf, &self.method);
        write_tl_string(&mut buf, &self.url);
        write_tl_string(&mut buf, &self.http_version);
        write_tl_vector(&mut buf, &self.headers);
        buf
    }

    /// Deserialize from TL bytes.
    pub fn from_tl_bytes(data: &[u8]) -> SiteResult<(Self, usize)> {
        if data.len() < 36 {
            return Err(SiteError::SerializationError("data too short".to_string()));
        }

        let id = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        if id != TL_HTTP_REQUEST {
            return Err(SiteError::SerializationError(format!(
                "unexpected TL ID: 0x{:08x}, expected http.request",
                id
            )));
        }

        let mut offset = 4;
        let mut request_id = [0u8; 32];
        request_id.copy_from_slice(&data[offset..offset + 32]);
        offset += 32;

        let (method, consumed) = read_tl_string(&data[offset..])?;
        offset += consumed;
        let (url, consumed) = read_tl_string(&data[offset..])?;
        offset += consumed;
        let (http_version, consumed) = read_tl_string(&data[offset..])?;
        offset += consumed;
        let (headers, consumed) = read_tl_vector(&data[offset..])?;
        offset += consumed;

        Ok((
            Self {
                id: request_id,
                method,
                url,
                http_version,
                headers,
            },
            offset,
        ))
    }
}

/// An HTTP response received over RLDP.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpResponse {
    /// HTTP version string.
    pub http_version: String,
    /// Status code (e.g., 200, 404).
    pub status_code: i32,
    /// Reason phrase (e.g., "OK", "Not Found").
    pub reason: String,
    /// Response headers.
    pub headers: Vec<HttpHeader>,
    /// Whether the response has no payload body.
    pub no_payload: bool,
}

impl HttpResponse {
    /// Create a new HTTP response.
    pub fn new(status_code: i32, reason: impl Into<String>) -> Self {
        Self {
            http_version: "HTTP/1.1".to_string(),
            status_code,
            reason: reason.into(),
            headers: Vec::new(),
            no_payload: true,
        }
    }

    /// Create a 200 OK response.
    pub fn ok() -> Self {
        Self::new(200, "OK")
    }

    /// Create a 404 Not Found response.
    pub fn not_found() -> Self {
        Self::new(404, "Not Found")
    }

    /// Add a header to the response.
    pub fn with_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.push(HttpHeader::new(name, value));
        self
    }

    /// Set whether the response has a payload.
    pub fn with_payload(mut self) -> Self {
        self.no_payload = false;
        self
    }

    /// Check if the response is successful (2xx status code).
    pub fn is_success(&self) -> bool {
        (200..300).contains(&self.status_code)
    }

    /// Check if the response is a redirect (3xx status code).
    pub fn is_redirect(&self) -> bool {
        (300..400).contains(&self.status_code)
    }

    /// Check if the response is a client error (4xx status code).
    pub fn is_client_error(&self) -> bool {
        (400..500).contains(&self.status_code)
    }

    /// Check if the response is a server error (5xx status code).
    pub fn is_server_error(&self) -> bool {
        (500..600).contains(&self.status_code)
    }

    /// Get a header value by name (case-insensitive).
    pub fn get_header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|h| h.name.eq_ignore_ascii_case(name))
            .map(|h| h.value.as_str())
    }

    /// Get the Content-Type header.
    pub fn content_type(&self) -> Option<&str> {
        self.get_header("Content-Type")
    }

    /// Get the Content-Length header as usize.
    pub fn content_length(&self) -> Option<usize> {
        self.get_header("Content-Length")
            .and_then(|v| v.parse().ok())
    }

    /// Serialize to TL bytes.
    pub fn to_tl_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&TL_HTTP_RESPONSE.to_le_bytes());
        write_tl_string(&mut buf, &self.http_version);
        buf.extend_from_slice(&self.status_code.to_le_bytes());
        write_tl_string(&mut buf, &self.reason);
        write_tl_vector(&mut buf, &self.headers);
        write_tl_bool(&mut buf, self.no_payload);
        buf
    }

    /// Deserialize from TL bytes.
    pub fn from_tl_bytes(data: &[u8]) -> SiteResult<(Self, usize)> {
        if data.len() < 8 {
            return Err(SiteError::SerializationError("data too short".to_string()));
        }

        let id = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        if id != TL_HTTP_RESPONSE {
            return Err(SiteError::SerializationError(format!(
                "unexpected TL ID: 0x{:08x}, expected http.response",
                id
            )));
        }

        let mut offset = 4;
        let (http_version, consumed) = read_tl_string(&data[offset..])?;
        offset += consumed;

        if data.len() < offset + 4 {
            return Err(SiteError::SerializationError("data too short".to_string()));
        }
        let status_code =
            i32::from_le_bytes([data[offset], data[offset + 1], data[offset + 2], data[offset + 3]]);
        offset += 4;

        let (reason, consumed) = read_tl_string(&data[offset..])?;
        offset += consumed;
        let (headers, consumed) = read_tl_vector(&data[offset..])?;
        offset += consumed;
        let (no_payload, consumed) = read_tl_bool(&data[offset..])?;
        offset += consumed;

        Ok((
            Self {
                http_version,
                status_code,
                reason,
                headers,
                no_payload,
            },
            offset,
        ))
    }
}

/// Request for the next payload part.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetNextPayloadPart {
    /// Request ID this payload belongs to.
    pub id: [u8; 32],
    /// Sequence number of the requested part.
    pub seqno: i32,
    /// Maximum chunk size to receive.
    pub max_chunk_size: i32,
}

impl GetNextPayloadPart {
    /// Create a new request for the next payload part.
    pub fn new(id: [u8; 32], seqno: i32, max_chunk_size: i32) -> Self {
        Self {
            id,
            seqno,
            max_chunk_size,
        }
    }

    /// Serialize to TL bytes.
    pub fn to_tl_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&TL_HTTP_GET_NEXT_PAYLOAD_PART.to_le_bytes());
        buf.extend_from_slice(&self.id);
        buf.extend_from_slice(&self.seqno.to_le_bytes());
        buf.extend_from_slice(&self.max_chunk_size.to_le_bytes());
        buf
    }

    /// Deserialize from TL bytes.
    pub fn from_tl_bytes(data: &[u8]) -> SiteResult<(Self, usize)> {
        if data.len() < 44 {
            return Err(SiteError::SerializationError("data too short".to_string()));
        }

        let id = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        if id != TL_HTTP_GET_NEXT_PAYLOAD_PART {
            return Err(SiteError::SerializationError(format!(
                "unexpected TL ID: 0x{:08x}, expected http.getNextPayloadPart",
                id
            )));
        }

        let mut offset = 4;
        let mut request_id = [0u8; 32];
        request_id.copy_from_slice(&data[offset..offset + 32]);
        offset += 32;

        let seqno =
            i32::from_le_bytes([data[offset], data[offset + 1], data[offset + 2], data[offset + 3]]);
        offset += 4;
        let max_chunk_size =
            i32::from_le_bytes([data[offset], data[offset + 1], data[offset + 2], data[offset + 3]]);
        offset += 4;

        Ok((
            Self {
                id: request_id,
                seqno,
                max_chunk_size,
            },
            offset,
        ))
    }
}

/// A payload part (chunk of request/response body).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PayloadPart {
    /// The data chunk.
    pub data: Vec<u8>,
    /// Trailer headers (usually empty except for the last part).
    pub trailer: Vec<HttpHeader>,
    /// Whether this is the last part.
    pub last: bool,
}

impl PayloadPart {
    /// Create a new payload part.
    pub fn new(data: Vec<u8>, last: bool) -> Self {
        Self {
            data,
            trailer: Vec::new(),
            last,
        }
    }

    /// Create an empty last payload part (for responses with no body).
    pub fn empty_last() -> Self {
        Self::new(Vec::new(), true)
    }

    /// Add trailer headers.
    pub fn with_trailer(mut self, trailer: Vec<HttpHeader>) -> Self {
        self.trailer = trailer;
        self
    }

    /// Serialize to TL bytes.
    pub fn to_tl_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&TL_HTTP_PAYLOAD_PART.to_le_bytes());
        write_tl_bytes(&mut buf, &self.data);
        write_tl_vector(&mut buf, &self.trailer);
        write_tl_bool(&mut buf, self.last);
        buf
    }

    /// Deserialize from TL bytes.
    pub fn from_tl_bytes(data: &[u8]) -> SiteResult<(Self, usize)> {
        if data.len() < 4 {
            return Err(SiteError::SerializationError("data too short".to_string()));
        }

        let id = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        if id != TL_HTTP_PAYLOAD_PART {
            return Err(SiteError::SerializationError(format!(
                "unexpected TL ID: 0x{:08x}, expected http.payloadPart",
                id
            )));
        }

        let mut offset = 4;
        let (payload_data, consumed) = read_tl_bytes(&data[offset..])?;
        offset += consumed;
        let (trailer, consumed) = read_tl_vector(&data[offset..])?;
        offset += consumed;
        let (last, consumed) = read_tl_bool(&data[offset..])?;
        offset += consumed;

        Ok((
            Self {
                data: payload_data,
                trailer,
                last,
            },
            offset,
        ))
    }
}

/// A complete HTTP response with body.
#[derive(Debug, Clone)]
pub struct FullHttpResponse {
    /// The response metadata.
    pub response: HttpResponse,
    /// The response body.
    pub body: Vec<u8>,
}

impl FullHttpResponse {
    /// Create a new full HTTP response.
    pub fn new(response: HttpResponse, body: Vec<u8>) -> Self {
        Self { response, body }
    }

    /// Create a response with no body.
    pub fn empty(response: HttpResponse) -> Self {
        Self::new(response, Vec::new())
    }

    /// Get the status code.
    pub fn status_code(&self) -> i32 {
        self.response.status_code
    }

    /// Check if the response is successful.
    pub fn is_success(&self) -> bool {
        self.response.is_success()
    }

    /// Get the body as a string (UTF-8).
    pub fn body_string(&self) -> Result<String, std::string::FromUtf8Error> {
        String::from_utf8(self.body.clone())
    }
}

// ============================================================================
// TL Serialization Helpers
// ============================================================================

/// Generate random bytes.
fn getrandom(buf: &mut [u8]) {
    use rand::RngCore;
    rand::thread_rng().fill_bytes(buf);
}

/// Write a TL string to buffer.
fn write_tl_string(buf: &mut Vec<u8>, s: &str) {
    write_tl_bytes(buf, s.as_bytes());
}

/// Write TL bytes to buffer (length-prefixed).
fn write_tl_bytes(buf: &mut Vec<u8>, data: &[u8]) {
    let len = data.len();
    if len < 254 {
        buf.push(len as u8);
        buf.extend_from_slice(data);
        // Padding to 4-byte boundary
        let pad = (4 - ((len + 1) % 4)) % 4;
        buf.extend(std::iter::repeat_n(0, pad));
    } else {
        buf.push(254);
        buf.push((len & 0xFF) as u8);
        buf.push(((len >> 8) & 0xFF) as u8);
        buf.push(((len >> 16) & 0xFF) as u8);
        buf.extend_from_slice(data);
        // Padding to 4-byte boundary
        let pad = (4 - (len % 4)) % 4;
        buf.extend(std::iter::repeat_n(0, pad));
    }
}

/// Write a TL bool to buffer.
fn write_tl_bool(buf: &mut Vec<u8>, value: bool) {
    // TL boolTrue = 0x997275b5, boolFalse = 0xbc799737
    if value {
        buf.extend_from_slice(&0x997275b5u32.to_le_bytes());
    } else {
        buf.extend_from_slice(&0xbc799737u32.to_le_bytes());
    }
}

/// Write a TL vector of headers to buffer.
fn write_tl_vector(buf: &mut Vec<u8>, headers: &[HttpHeader]) {
    // TL vector constructor
    buf.extend_from_slice(&0x1cb5c415u32.to_le_bytes());
    buf.extend_from_slice(&(headers.len() as u32).to_le_bytes());
    for header in headers {
        // For vector elements, we write without the outer constructor ID
        write_tl_string(buf, &header.name);
        write_tl_string(buf, &header.value);
    }
}

/// Read a TL string from buffer.
fn read_tl_string(data: &[u8]) -> SiteResult<(String, usize)> {
    let (bytes, consumed) = read_tl_bytes(data)?;
    let s = String::from_utf8(bytes)
        .map_err(|e| SiteError::SerializationError(format!("invalid UTF-8: {}", e)))?;
    Ok((s, consumed))
}

/// Read TL bytes from buffer (length-prefixed).
fn read_tl_bytes(data: &[u8]) -> SiteResult<(Vec<u8>, usize)> {
    if data.is_empty() {
        return Err(SiteError::SerializationError("data too short".to_string()));
    }

    let (len, header_size) = if data[0] < 254 {
        (data[0] as usize, 1)
    } else {
        if data.len() < 4 {
            return Err(SiteError::SerializationError("data too short".to_string()));
        }
        let len = data[1] as usize | ((data[2] as usize) << 8) | ((data[3] as usize) << 16);
        (len, 4)
    };

    if data.len() < header_size + len {
        return Err(SiteError::SerializationError("data too short".to_string()));
    }

    let bytes = data[header_size..header_size + len].to_vec();

    // Calculate padding
    let total_len = header_size + len;
    let padded_len = (total_len + 3) & !3;

    Ok((bytes, padded_len))
}

/// Read a TL bool from buffer.
fn read_tl_bool(data: &[u8]) -> SiteResult<(bool, usize)> {
    if data.len() < 4 {
        return Err(SiteError::SerializationError("data too short".to_string()));
    }

    let id = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    match id {
        0x997275b5 => Ok((true, 4)),
        0xbc799737 => Ok((false, 4)),
        _ => Err(SiteError::SerializationError(format!(
            "invalid bool TL ID: 0x{:08x}",
            id
        ))),
    }
}

/// Read a TL vector of headers from buffer.
fn read_tl_vector(data: &[u8]) -> SiteResult<(Vec<HttpHeader>, usize)> {
    if data.len() < 8 {
        return Err(SiteError::SerializationError("data too short".to_string()));
    }

    let id = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    if id != 0x1cb5c415 {
        return Err(SiteError::SerializationError(format!(
            "invalid vector TL ID: 0x{:08x}",
            id
        )));
    }

    let count = u32::from_le_bytes([data[4], data[5], data[6], data[7]]) as usize;
    let mut offset = 8;
    let mut headers = Vec::with_capacity(count);

    for _ in 0..count {
        // Vector elements don't have their own constructor ID
        let (name, consumed) = read_tl_string(&data[offset..])?;
        offset += consumed;
        let (value, consumed) = read_tl_string(&data[offset..])?;
        offset += consumed;
        headers.push(HttpHeader { name, value });
    }

    Ok((headers, offset))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_http_header_roundtrip() {
        let header = HttpHeader::new("Content-Type", "text/html");
        let bytes = header.to_tl_bytes();
        let (parsed, _) = HttpHeader::from_tl_bytes(&bytes).unwrap();
        assert_eq!(header, parsed);
    }

    #[test]
    fn test_http_request_roundtrip() {
        let request = HttpRequest::get("/index.html")
            .with_host("example.ton")
            .with_header("Accept", "text/html");

        let bytes = request.to_tl_bytes();
        let (parsed, _) = HttpRequest::from_tl_bytes(&bytes).unwrap();

        assert_eq!(request.id, parsed.id);
        assert_eq!(request.method, parsed.method);
        assert_eq!(request.url, parsed.url);
        assert_eq!(request.http_version, parsed.http_version);
        assert_eq!(request.headers.len(), parsed.headers.len());
    }

    #[test]
    fn test_http_response_roundtrip() {
        let response = HttpResponse::ok()
            .with_header("Content-Type", "text/html")
            .with_header("Content-Length", "1234")
            .with_payload();

        let bytes = response.to_tl_bytes();
        let (parsed, _) = HttpResponse::from_tl_bytes(&bytes).unwrap();

        assert_eq!(response.http_version, parsed.http_version);
        assert_eq!(response.status_code, parsed.status_code);
        assert_eq!(response.reason, parsed.reason);
        assert_eq!(response.no_payload, parsed.no_payload);
        assert_eq!(response.headers.len(), parsed.headers.len());
    }

    #[test]
    fn test_get_next_payload_part_roundtrip() {
        let req = GetNextPayloadPart::new([0xAB; 32], 5, 128 * 1024);
        let bytes = req.to_tl_bytes();
        let (parsed, _) = GetNextPayloadPart::from_tl_bytes(&bytes).unwrap();

        assert_eq!(req.id, parsed.id);
        assert_eq!(req.seqno, parsed.seqno);
        assert_eq!(req.max_chunk_size, parsed.max_chunk_size);
    }

    #[test]
    fn test_payload_part_roundtrip() {
        let part = PayloadPart::new(b"Hello, TON Sites!".to_vec(), false);
        let bytes = part.to_tl_bytes();
        let (parsed, _) = PayloadPart::from_tl_bytes(&bytes).unwrap();

        assert_eq!(part.data, parsed.data);
        assert_eq!(part.last, parsed.last);
        assert_eq!(part.trailer.len(), parsed.trailer.len());
    }

    #[test]
    fn test_payload_part_last() {
        let part = PayloadPart::empty_last();
        let bytes = part.to_tl_bytes();
        let (parsed, _) = PayloadPart::from_tl_bytes(&bytes).unwrap();

        assert!(parsed.data.is_empty());
        assert!(parsed.last);
    }

    #[test]
    fn test_http_response_status_checks() {
        let ok = HttpResponse::new(200, "OK");
        assert!(ok.is_success());
        assert!(!ok.is_redirect());
        assert!(!ok.is_client_error());
        assert!(!ok.is_server_error());

        let redirect = HttpResponse::new(301, "Moved Permanently");
        assert!(!redirect.is_success());
        assert!(redirect.is_redirect());

        let not_found = HttpResponse::new(404, "Not Found");
        assert!(!not_found.is_success());
        assert!(not_found.is_client_error());

        let server_error = HttpResponse::new(500, "Internal Server Error");
        assert!(!server_error.is_success());
        assert!(server_error.is_server_error());
    }

    #[test]
    fn test_http_response_get_header() {
        let response = HttpResponse::ok()
            .with_header("Content-Type", "text/html")
            .with_header("X-Custom", "value");

        assert_eq!(response.get_header("Content-Type"), Some("text/html"));
        assert_eq!(response.get_header("content-type"), Some("text/html")); // case insensitive
        assert_eq!(response.get_header("X-Custom"), Some("value"));
        assert_eq!(response.get_header("Missing"), None);
    }

    #[test]
    fn test_tl_string_roundtrip() {
        let long_string_100 = "x".repeat(100);
        let long_string_300 = "y".repeat(300);
        let test_strings: Vec<&str> = vec![
            "",
            "a",
            "hello",
            "Hello, World!",
            &long_string_100,
            &long_string_300, // > 254 bytes
        ];

        for s in test_strings {
            let mut buf = Vec::new();
            write_tl_string(&mut buf, s);
            let (parsed, _) = read_tl_string(&buf).unwrap();
            assert_eq!(s, parsed, "Failed for string of length {}", s.len());
        }
    }

    #[test]
    fn test_tl_bytes_roundtrip() {
        let test_data = vec![
            vec![],
            vec![0],
            vec![1, 2, 3],
            vec![0u8; 100],
            vec![0xABu8; 300], // > 254 bytes
        ];

        for data in test_data {
            let mut buf = Vec::new();
            write_tl_bytes(&mut buf, &data);
            let (parsed, _) = read_tl_bytes(&buf).unwrap();
            assert_eq!(data, parsed, "Failed for data of length {}", data.len());
        }
    }

    #[test]
    fn test_tl_bool_roundtrip() {
        for value in [true, false] {
            let mut buf = Vec::new();
            write_tl_bool(&mut buf, value);
            let (parsed, _) = read_tl_bool(&buf).unwrap();
            assert_eq!(value, parsed);
        }
    }

    #[test]
    fn test_full_http_response() {
        let response = HttpResponse::ok().with_header("Content-Type", "text/plain");
        let body = b"Hello, World!".to_vec();
        let full = FullHttpResponse::new(response, body.clone());

        assert_eq!(full.status_code(), 200);
        assert!(full.is_success());
        assert_eq!(full.body_string().unwrap(), "Hello, World!");
    }
}
