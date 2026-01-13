//! URL parsing for TON Sites.
//!
//! This module provides URL parsing for .ton and .adnl domains.
//!
//! # Supported URL Formats
//!
//! - `http://example.ton/path` - HTTP to a .ton domain
//! - `https://example.ton/path` - HTTPS to a .ton domain (note: connection is still via RLDP)
//! - `ton://example.ton/path` - TON-specific scheme
//! - `http://abcd1234...5678.adnl/path` - Direct ADNL address access
//!
//! # Example
//!
//! ```
//! use ton_sites::url::{parse_ton_url, TonUrl};
//!
//! let url = parse_ton_url("http://example.ton/index.html").unwrap();
//! assert_eq!(url.domain, "example.ton");
//! assert_eq!(url.path, "/index.html");
//! assert!(url.is_ton_domain());
//!
//! let url = parse_ton_url("http://sub.example.ton/").unwrap();
//! assert_eq!(url.domain, "sub.example.ton");
//! ```

use crate::error::{SiteError, SiteResult};

/// A parsed TON URL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TonUrl {
    /// The scheme (http, https, or ton).
    pub scheme: String,
    /// The domain (e.g., "example.ton" or "abc...def.adnl").
    pub domain: String,
    /// Optional port number.
    pub port: Option<u16>,
    /// The path (e.g., "/index.html").
    pub path: String,
    /// Optional query string (without the leading ?).
    pub query: Option<String>,
    /// Optional fragment (without the leading #).
    pub fragment: Option<String>,
}

impl TonUrl {
    /// Check if this is a .ton domain.
    pub fn is_ton_domain(&self) -> bool {
        self.domain.ends_with(".ton")
    }

    /// Check if this is a .adnl address.
    pub fn is_adnl_address(&self) -> bool {
        self.domain.ends_with(".adnl")
    }

    /// Get the ADNL address if this is a .adnl URL.
    ///
    /// Returns the hex-encoded address without the ".adnl" suffix.
    pub fn adnl_address_hex(&self) -> Option<&str> {
        if self.is_adnl_address() {
            Some(self.domain.strip_suffix(".adnl").unwrap_or(&self.domain))
        } else {
            None
        }
    }

    /// Parse the ADNL address into a 32-byte array.
    pub fn parse_adnl_address(&self) -> SiteResult<[u8; 32]> {
        let hex_addr = self.adnl_address_hex().ok_or_else(|| {
            SiteError::InvalidDomain(format!("{} is not an .adnl address", self.domain))
        })?;

        parse_adnl_address(hex_addr)
    }

    /// Get the full path including query string.
    pub fn full_path(&self) -> String {
        match &self.query {
            Some(q) => format!("{}?{}", self.path, q),
            None => self.path.clone(),
        }
    }

    /// Get the host header value.
    pub fn host(&self) -> String {
        match self.port {
            Some(p) => format!("{}:{}", self.domain, p),
            None => self.domain.clone(),
        }
    }

}

impl std::fmt::Display for TonUrl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}://{}", self.scheme, self.domain)?;
        if let Some(port) = self.port {
            write!(f, ":{}", port)?;
        }
        write!(f, "{}", self.path)?;
        if let Some(query) = &self.query {
            write!(f, "?{}", query)?;
        }
        if let Some(fragment) = &self.fragment {
            write!(f, "#{}", fragment)?;
        }
        Ok(())
    }
}

/// Parse a TON URL.
///
/// # Arguments
///
/// * `url` - The URL string to parse
///
/// # Returns
///
/// A parsed `TonUrl` if the URL is valid, or an error if it's not.
///
/// # Examples
///
/// ```
/// use ton_sites::url::parse_ton_url;
///
/// // Parse a simple .ton URL
/// let url = parse_ton_url("http://example.ton/").unwrap();
/// assert_eq!(url.domain, "example.ton");
/// assert_eq!(url.path, "/");
///
/// // Parse a URL with path and query
/// let url = parse_ton_url("http://app.ton/api/v1?key=value").unwrap();
/// assert_eq!(url.path, "/api/v1");
/// assert_eq!(url.query, Some("key=value".to_string()));
/// ```
pub fn parse_ton_url(url: &str) -> SiteResult<TonUrl> {
    // Find scheme
    let (scheme, rest) = url
        .split_once("://")
        .ok_or_else(|| SiteError::InvalidUrl("missing scheme (expected http://, https://, or ton://)".to_string()))?;

    // Validate scheme
    let scheme = scheme.to_lowercase();
    if !matches!(scheme.as_str(), "http" | "https" | "ton") {
        return Err(SiteError::InvalidUrl(format!(
            "unsupported scheme: {}. Expected http, https, or ton",
            scheme
        )));
    }

    // Split authority from path
    let (authority, path_and_rest) = match rest.find('/') {
        Some(idx) => (&rest[..idx], &rest[idx..]),
        None => (rest, "/"),
    };

    // Parse authority (domain:port)
    let (domain, port) = if let Some(bracket_end) = authority.find(']') {
        // IPv6 address (shouldn't happen for TON, but handle gracefully)
        let port_part = &authority[bracket_end + 1..];
        let port = if let Some(stripped) = port_part.strip_prefix(':') {
            Some(stripped.parse().map_err(|_| {
                SiteError::InvalidUrl("invalid port number".to_string())
            })?)
        } else {
            None
        };
        (&authority[..bracket_end + 1], port)
    } else if let Some(colon_idx) = authority.rfind(':') {
        // Check if it's a port or just part of the domain
        let potential_port = &authority[colon_idx + 1..];
        if potential_port.chars().all(|c| c.is_ascii_digit()) && !potential_port.is_empty() {
            let port: u16 = potential_port.parse().map_err(|_| {
                SiteError::InvalidUrl("invalid port number".to_string())
            })?;
            (&authority[..colon_idx], Some(port))
        } else {
            (authority, None)
        }
    } else {
        (authority, None)
    };

    let domain = domain.to_lowercase();

    // Validate domain
    if domain.is_empty() {
        return Err(SiteError::InvalidUrl("empty domain".to_string()));
    }

    if !domain.ends_with(".ton") && !domain.ends_with(".adnl") {
        return Err(SiteError::InvalidDomain(domain));
    }

    // Validate .adnl address format
    if domain.ends_with(".adnl") {
        let hex_part = domain.strip_suffix(".adnl").unwrap();
        if hex_part.len() != 64 {
            return Err(SiteError::InvalidAdnlAddress(format!(
                "ADNL address must be 64 hex characters, got {}",
                hex_part.len()
            )));
        }
        if !hex_part.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(SiteError::InvalidAdnlAddress(
                "ADNL address must contain only hex characters".to_string(),
            ));
        }
    }

    // Parse path, query, and fragment
    let (path_and_query, fragment) = match path_and_rest.split_once('#') {
        Some((p, f)) => (p, Some(f.to_string())),
        None => (path_and_rest, None),
    };

    let (path, query) = match path_and_query.split_once('?') {
        Some((p, q)) => (p.to_string(), Some(q.to_string())),
        None => (path_and_query.to_string(), None),
    };

    // Ensure path starts with /
    let path = if path.is_empty() || !path.starts_with('/') {
        format!("/{}", path)
    } else {
        path
    };

    Ok(TonUrl {
        scheme,
        domain,
        port,
        path,
        query,
        fragment,
    })
}

/// Parse an ADNL address from hex string.
///
/// # Arguments
///
/// * `hex` - A 64-character hex string representing the 32-byte ADNL address
///
/// # Returns
///
/// A 32-byte array containing the ADNL address.
pub fn parse_adnl_address(hex: &str) -> SiteResult<[u8; 32]> {
    if hex.len() != 64 {
        return Err(SiteError::InvalidAdnlAddress(format!(
            "ADNL address must be 64 hex characters, got {}",
            hex.len()
        )));
    }

    let bytes = hex::decode(hex).map_err(|e| {
        SiteError::InvalidAdnlAddress(format!("invalid hex: {}", e))
    })?;

    let mut addr = [0u8; 32];
    addr.copy_from_slice(&bytes);
    Ok(addr)
}

/// Format an ADNL address as a hex string.
pub fn format_adnl_address(addr: &[u8; 32]) -> String {
    hex::encode(addr)
}

/// Create an .adnl domain from a raw ADNL address.
pub fn adnl_to_domain(addr: &[u8; 32]) -> String {
    format!("{}.adnl", format_adnl_address(addr))
}

/// Extract domain and path from a URL string.
///
/// This is a simpler version of `parse_ton_url` that just returns
/// the domain and path.
pub fn extract_domain_and_path(url: &str) -> SiteResult<(String, String)> {
    let parsed = parse_ton_url(url)?;
    let path = parsed.full_path();
    Ok((parsed.domain, path))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_ton_url() {
        let url = parse_ton_url("http://example.ton/").unwrap();
        assert_eq!(url.scheme, "http");
        assert_eq!(url.domain, "example.ton");
        assert_eq!(url.port, None);
        assert_eq!(url.path, "/");
        assert_eq!(url.query, None);
        assert_eq!(url.fragment, None);
        assert!(url.is_ton_domain());
        assert!(!url.is_adnl_address());
    }

    #[test]
    fn test_parse_ton_url_with_path() {
        let url = parse_ton_url("http://example.ton/index.html").unwrap();
        assert_eq!(url.domain, "example.ton");
        assert_eq!(url.path, "/index.html");
    }

    #[test]
    fn test_parse_ton_url_with_subdomain() {
        let url = parse_ton_url("http://sub.example.ton/api/v1").unwrap();
        assert_eq!(url.domain, "sub.example.ton");
        assert_eq!(url.path, "/api/v1");
    }

    #[test]
    fn test_parse_ton_url_with_query() {
        let url = parse_ton_url("http://example.ton/search?q=hello&page=1").unwrap();
        assert_eq!(url.path, "/search");
        assert_eq!(url.query, Some("q=hello&page=1".to_string()));
        assert_eq!(url.full_path(), "/search?q=hello&page=1");
    }

    #[test]
    fn test_parse_ton_url_with_fragment() {
        let url = parse_ton_url("http://example.ton/page#section").unwrap();
        assert_eq!(url.path, "/page");
        assert_eq!(url.fragment, Some("section".to_string()));
    }

    #[test]
    fn test_parse_ton_url_with_port() {
        let url = parse_ton_url("http://example.ton:8080/api").unwrap();
        assert_eq!(url.domain, "example.ton");
        assert_eq!(url.port, Some(8080));
        assert_eq!(url.host(), "example.ton:8080");
    }

    #[test]
    fn test_parse_https_url() {
        let url = parse_ton_url("https://secure.ton/").unwrap();
        assert_eq!(url.scheme, "https");
        assert_eq!(url.domain, "secure.ton");
    }

    #[test]
    fn test_parse_ton_scheme() {
        let url = parse_ton_url("ton://example.ton/").unwrap();
        assert_eq!(url.scheme, "ton");
        assert_eq!(url.domain, "example.ton");
    }

    #[test]
    fn test_parse_adnl_url() {
        let addr_hex = "a".repeat(64);
        let url_str = format!("http://{}.adnl/page", addr_hex);
        let url = parse_ton_url(&url_str).unwrap();

        assert_eq!(url.domain, format!("{}.adnl", addr_hex));
        assert!(url.is_adnl_address());
        assert!(!url.is_ton_domain());
        assert_eq!(url.adnl_address_hex(), Some(addr_hex.as_str()));
    }

    #[test]
    fn test_parse_adnl_address_from_url() {
        let addr = [0xAB; 32];
        let addr_hex = hex::encode(addr);
        let url_str = format!("http://{}.adnl/", addr_hex);
        let url = parse_ton_url(&url_str).unwrap();

        let parsed_addr = url.parse_adnl_address().unwrap();
        assert_eq!(parsed_addr, addr);
    }

    #[test]
    fn test_case_insensitive() {
        let url = parse_ton_url("HTTP://EXAMPLE.TON/PATH").unwrap();
        assert_eq!(url.scheme, "http");
        assert_eq!(url.domain, "example.ton");
        // Path preserves case
        assert_eq!(url.path, "/PATH");
    }

    #[test]
    fn test_url_without_path() {
        let url = parse_ton_url("http://example.ton").unwrap();
        assert_eq!(url.domain, "example.ton");
        assert_eq!(url.path, "/");
    }

    #[test]
    fn test_url_to_string() {
        let url = TonUrl {
            scheme: "http".to_string(),
            domain: "example.ton".to_string(),
            port: Some(8080),
            path: "/api".to_string(),
            query: Some("key=value".to_string()),
            fragment: Some("section".to_string()),
        };

        assert_eq!(url.to_string(), "http://example.ton:8080/api?key=value#section");
    }

    #[test]
    fn test_invalid_scheme() {
        let result = parse_ton_url("ftp://example.ton/");
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), SiteError::InvalidUrl(_)));
    }

    #[test]
    fn test_invalid_domain() {
        let result = parse_ton_url("http://example.com/");
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), SiteError::InvalidDomain(_)));
    }

    #[test]
    fn test_missing_scheme() {
        let result = parse_ton_url("example.ton/");
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), SiteError::InvalidUrl(_)));
    }

    #[test]
    fn test_invalid_adnl_address_length() {
        let result = parse_ton_url("http://abc123.adnl/");
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), SiteError::InvalidAdnlAddress(_)));
    }

    #[test]
    fn test_invalid_adnl_address_chars() {
        let addr = format!("{}xyz{}", "a".repeat(30), "a".repeat(31));
        let result = parse_ton_url(&format!("http://{}.adnl/", addr));
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), SiteError::InvalidAdnlAddress(_)));
    }

    #[test]
    fn test_parse_adnl_address() {
        let addr = [0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0,
                    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
                    0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00,
                    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];

        let hex = format_adnl_address(&addr);
        let parsed = parse_adnl_address(&hex).unwrap();
        assert_eq!(parsed, addr);
    }

    #[test]
    fn test_adnl_to_domain() {
        let addr = [0xAB; 32];
        let domain = adnl_to_domain(&addr);
        assert_eq!(domain, format!("{}.adnl", hex::encode(addr)));
    }

    #[test]
    fn test_extract_domain_and_path() {
        let (domain, path) = extract_domain_and_path("http://example.ton/api?foo=bar").unwrap();
        assert_eq!(domain, "example.ton");
        assert_eq!(path, "/api?foo=bar");
    }

    #[test]
    fn test_complex_path() {
        let url = parse_ton_url("http://app.ton/api/v2/users/123/profile").unwrap();
        assert_eq!(url.path, "/api/v2/users/123/profile");
    }

    #[test]
    fn test_empty_query_and_fragment() {
        // URL with ? but no query value
        let url = parse_ton_url("http://example.ton/page?").unwrap();
        assert_eq!(url.query, Some("".to_string()));

        // URL with # but no fragment value
        let url = parse_ton_url("http://example.ton/page#").unwrap();
        assert_eq!(url.fragment, Some("".to_string()));
    }

    #[test]
    fn test_deeply_nested_subdomain() {
        let url = parse_ton_url("http://a.b.c.d.e.ton/").unwrap();
        assert_eq!(url.domain, "a.b.c.d.e.ton");
        assert!(url.is_ton_domain());
    }
}
