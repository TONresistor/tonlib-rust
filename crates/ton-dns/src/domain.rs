//! Domain parsing, validation, and internal representation conversion.
//!
//! TON DNS domains follow specific rules:
//! - Must end with `.ton` or `.t.me` (Telegram usernames via Fragment)
//! - UTF-8 encoded, max 126 bytes per component
//! - Bytes 0-32 are prohibited (control characters)
//! - Case-sensitive internally, but applications typically convert to lowercase
//!
//! # Internal Representation
//!
//! For DNS resolution, domains are converted to an internal format:
//! - Components are reversed (e.g., "test.ton" -> "ton", "test")
//! - Each component is followed by a null byte
//! - Example: "test.ton" -> b"ton\0test\0"
//! - Example: "user.t.me" -> b"me\0t\0user\0"

use crate::error::{DnsError, DnsResult};

/// Maximum length of a domain component in bytes.
pub const MAX_COMPONENT_LENGTH: usize = 126;

/// The required TLD for TON domains.
pub const TON_TLD: &str = "ton";

/// The TLD for Telegram usernames (via Fragment).
pub const TME_TLD: &str = "t.me";

/// A validated TON domain name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TonDomain {
    /// The original domain string (e.g., "test.ton").
    domain: String,
    /// The domain components, in original order (e.g., ["test", "ton"]).
    components: Vec<String>,
}

impl TonDomain {
    /// Parse and validate a TON domain name.
    ///
    /// # Arguments
    ///
    /// * `domain` - The domain name to parse (e.g., "test.ton")
    ///
    /// # Returns
    ///
    /// A validated `TonDomain` or an error if invalid.
    ///
    /// # Examples
    ///
    /// ```
    /// use ton_dns::domain::TonDomain;
    ///
    /// let domain = TonDomain::parse("test.ton").unwrap();
    /// assert_eq!(domain.as_str(), "test.ton");
    ///
    /// // Invalid domains return errors
    /// assert!(TonDomain::parse("").is_err());
    /// assert!(TonDomain::parse("test.com").is_err());
    /// ```
    pub fn parse(domain: &str) -> DnsResult<Self> {
        // Check for empty domain
        if domain.is_empty() {
            return Err(DnsError::InvalidDomain("domain cannot be empty".to_string()));
        }

        // Split into components
        let components: Vec<&str> = domain.split('.').collect();

        // Check for valid TLD: .ton or .t.me
        let is_ton_domain = components.last() == Some(&"ton");
        let is_tme_domain = components.len() >= 3
            && components[components.len() - 2] == "t"
            && components[components.len() - 1] == "me";

        if !is_ton_domain && !is_tme_domain {
            return Err(DnsError::InvalidTld(domain.to_string()));
        }

        // Must have at least one name component before TLD
        let min_components = if is_tme_domain { 3 } else { 2 }; // "x.t.me" or "x.ton"
        if components.len() < min_components {
            return Err(DnsError::InvalidTld(domain.to_string()));
        }

        // Validate each component
        for component in &components {
            validate_component(component)?;
        }

        Ok(Self {
            domain: domain.to_string(),
            components: components.into_iter().map(String::from).collect(),
        })
    }

    /// Parse and normalize a domain to lowercase.
    ///
    /// TON DNS is case-sensitive internally, but applications typically
    /// convert domains to lowercase before resolution.
    ///
    /// # Examples
    ///
    /// ```
    /// use ton_dns::domain::TonDomain;
    ///
    /// let domain = TonDomain::parse_normalized("Test.TON").unwrap();
    /// assert_eq!(domain.as_str(), "test.ton");
    /// ```
    pub fn parse_normalized(domain: &str) -> DnsResult<Self> {
        Self::parse(&domain.to_lowercase())
    }

    /// Get the original domain string.
    pub fn as_str(&self) -> &str {
        &self.domain
    }

    /// Get the domain components in original order.
    pub fn components(&self) -> &[String] {
        &self.components
    }

    /// Get the domain name without the .ton suffix.
    ///
    /// For "test.example.ton", returns "test.example".
    pub fn name(&self) -> String {
        self.components[..self.components.len() - 1].join(".")
    }

    /// Convert to internal representation for DNS resolution.
    ///
    /// The internal format reverses components and adds null terminators:
    /// - "test.ton" -> b"ton\0test\0"
    /// - "sub.test.ton" -> b"ton\0test\0sub\0"
    ///
    /// # Examples
    ///
    /// ```
    /// use ton_dns::domain::TonDomain;
    ///
    /// let domain = TonDomain::parse("test.ton").unwrap();
    /// assert_eq!(domain.to_internal(), b"ton\0test\0");
    ///
    /// let domain = TonDomain::parse("sub.test.ton").unwrap();
    /// assert_eq!(domain.to_internal(), b"ton\0test\0sub\0");
    /// ```
    pub fn to_internal(&self) -> Vec<u8> {
        domain_to_internal(&self.domain)
    }
}

impl std::fmt::Display for TonDomain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.domain)
    }
}

impl std::str::FromStr for TonDomain {
    type Err = DnsError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

/// Validate a single domain component.
///
/// A component must:
/// - Not be empty
/// - Be at most 126 bytes
/// - Not contain control characters (bytes 0-32)
fn validate_component(component: &str) -> DnsResult<()> {
    // Check for empty component
    if component.is_empty() {
        return Err(DnsError::InvalidDomain(
            "domain component cannot be empty".to_string(),
        ));
    }

    // Check length
    let len = component.len();
    if len > MAX_COMPONENT_LENGTH {
        return Err(DnsError::ComponentTooLong { length: len });
    }

    // Check for invalid characters (control characters 0-32)
    for byte in component.bytes() {
        if byte <= 32 {
            return Err(DnsError::InvalidCharacter { byte });
        }
    }

    Ok(())
}

/// Convert a domain string to its internal representation.
///
/// This is the raw conversion function. For validated domains, use
/// `TonDomain::to_internal()`.
///
/// # Algorithm
///
/// 1. Split domain by '.'
/// 2. Reverse the order of components
/// 3. Join with null bytes, ending with a null byte
///
/// # Examples
///
/// ```
/// use ton_dns::domain::domain_to_internal;
///
/// assert_eq!(domain_to_internal("test.ton"), b"ton\0test\0");
/// assert_eq!(domain_to_internal("sub.test.ton"), b"ton\0test\0sub\0");
/// ```
pub fn domain_to_internal(domain: &str) -> Vec<u8> {
    let parts: Vec<&str> = domain.split('.').collect();
    let mut result = Vec::new();

    for part in parts.iter().rev() {
        result.extend_from_slice(part.as_bytes());
        result.push(0);
    }

    result
}

/// Convert internal representation back to a domain string.
///
/// This is the inverse of `domain_to_internal()`.
///
/// # Examples
///
/// ```
/// use ton_dns::domain::{domain_to_internal, internal_to_domain};
///
/// let internal = domain_to_internal("test.ton");
/// assert_eq!(internal_to_domain(&internal).unwrap(), "test.ton");
/// ```
pub fn internal_to_domain(internal: &[u8]) -> DnsResult<String> {
    if internal.is_empty() {
        return Err(DnsError::InvalidDomain("empty internal representation".to_string()));
    }

    let mut parts = Vec::new();
    let mut current = Vec::new();

    for &byte in internal {
        if byte == 0 {
            if current.is_empty() {
                return Err(DnsError::InvalidDomain(
                    "empty component in internal representation".to_string(),
                ));
            }
            let part = String::from_utf8(current.clone())
                .map_err(|e| DnsError::InvalidDomain(format!("invalid UTF-8: {}", e)))?;
            parts.push(part);
            current.clear();
        } else {
            current.push(byte);
        }
    }

    // Handle case where internal doesn't end with null
    if !current.is_empty() {
        let part = String::from_utf8(current)
            .map_err(|e| DnsError::InvalidDomain(format!("invalid UTF-8: {}", e)))?;
        parts.push(part);
    }

    // Reverse to get original order
    parts.reverse();
    Ok(parts.join("."))
}

/// Calculate how many bytes of internal representation were resolved.
///
/// Given a number of resolved bits, calculates the byte count.
/// DNS resolution returns the number of resolved bits.
pub fn resolved_bytes(resolved_bits: usize) -> usize {
    resolved_bits / 8
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_valid_domain() {
        let domain = TonDomain::parse("test.ton").unwrap();
        assert_eq!(domain.as_str(), "test.ton");
        assert_eq!(domain.components(), &["test", "ton"]);
        assert_eq!(domain.name(), "test");
    }

    #[test]
    fn test_parse_subdomain() {
        let domain = TonDomain::parse("sub.test.ton").unwrap();
        assert_eq!(domain.as_str(), "sub.test.ton");
        assert_eq!(domain.components(), &["sub", "test", "ton"]);
        assert_eq!(domain.name(), "sub.test");
    }

    #[test]
    fn test_parse_deep_subdomain() {
        let domain = TonDomain::parse("a.b.c.test.ton").unwrap();
        assert_eq!(domain.components(), &["a", "b", "c", "test", "ton"]);
        assert_eq!(domain.name(), "a.b.c.test");
    }

    #[test]
    fn test_parse_empty_domain() {
        let result = TonDomain::parse("");
        assert!(matches!(result, Err(DnsError::InvalidDomain(_))));
    }

    #[test]
    fn test_parse_invalid_tld() {
        let result = TonDomain::parse("test.com");
        assert!(matches!(result, Err(DnsError::InvalidTld(_))));

        let result = TonDomain::parse("test.TON"); // Case-sensitive
        assert!(matches!(result, Err(DnsError::InvalidTld(_))));
    }

    #[test]
    fn test_parse_no_tld() {
        let result = TonDomain::parse("test");
        assert!(matches!(result, Err(DnsError::InvalidTld(_))));
    }

    #[test]
    fn test_parse_empty_component() {
        let result = TonDomain::parse(".ton");
        assert!(matches!(result, Err(DnsError::InvalidDomain(_))));

        let result = TonDomain::parse("test..ton");
        assert!(matches!(result, Err(DnsError::InvalidDomain(_))));
    }

    #[test]
    fn test_parse_component_too_long() {
        let long_component = "a".repeat(127);
        let domain = format!("{}.ton", long_component);
        let result = TonDomain::parse(&domain);
        assert!(matches!(result, Err(DnsError::ComponentTooLong { length: 127 })));
    }

    #[test]
    fn test_parse_max_length_component() {
        let max_component = "a".repeat(126);
        let domain = format!("{}.ton", max_component);
        let result = TonDomain::parse(&domain);
        assert!(result.is_ok());
    }

    #[test]
    fn test_parse_control_characters() {
        // Tab character (byte 9)
        let result = TonDomain::parse("test\t.ton");
        assert!(matches!(result, Err(DnsError::InvalidCharacter { byte: 9 })));

        // Newline (byte 10)
        let result = TonDomain::parse("test\n.ton");
        assert!(matches!(result, Err(DnsError::InvalidCharacter { byte: 10 })));

        // Space (byte 32)
        let result = TonDomain::parse("test name.ton");
        assert!(matches!(result, Err(DnsError::InvalidCharacter { byte: 32 })));

        // Null byte (byte 0)
        let result = TonDomain::parse("test\0.ton");
        assert!(matches!(result, Err(DnsError::InvalidCharacter { byte: 0 })));
    }

    #[test]
    fn test_parse_normalized() {
        let domain = TonDomain::parse_normalized("Test.TON").unwrap();
        assert_eq!(domain.as_str(), "test.ton");

        let domain = TonDomain::parse_normalized("SUB.TEST.TON").unwrap();
        assert_eq!(domain.as_str(), "sub.test.ton");
    }

    #[test]
    fn test_domain_to_internal() {
        assert_eq!(domain_to_internal("test.ton"), b"ton\0test\0");
        assert_eq!(domain_to_internal("sub.test.ton"), b"ton\0test\0sub\0");
        assert_eq!(
            domain_to_internal("a.b.c.ton"),
            b"ton\0c\0b\0a\0"
        );
    }

    #[test]
    fn test_internal_to_domain() {
        assert_eq!(
            internal_to_domain(b"ton\0test\0").unwrap(),
            "test.ton"
        );
        assert_eq!(
            internal_to_domain(b"ton\0test\0sub\0").unwrap(),
            "sub.test.ton"
        );
        assert_eq!(
            internal_to_domain(b"ton\0c\0b\0a\0").unwrap(),
            "a.b.c.ton"
        );
    }

    #[test]
    fn test_roundtrip() {
        let domains = ["test.ton", "sub.test.ton", "a.b.c.d.ton"];

        for domain_str in domains {
            let domain = TonDomain::parse(domain_str).unwrap();
            let internal = domain.to_internal();
            let recovered = internal_to_domain(&internal).unwrap();
            assert_eq!(recovered, domain_str);
        }
    }

    #[test]
    fn test_resolved_bytes() {
        assert_eq!(resolved_bytes(0), 0);
        assert_eq!(resolved_bytes(8), 1);
        assert_eq!(resolved_bytes(16), 2);
        assert_eq!(resolved_bytes(32), 4);
        assert_eq!(resolved_bytes(33), 4); // Partial byte not counted
    }

    #[test]
    fn test_from_str() {
        let domain: TonDomain = "test.ton".parse().unwrap();
        assert_eq!(domain.as_str(), "test.ton");

        let result: Result<TonDomain, _> = "invalid".parse();
        assert!(result.is_err());
    }

    #[test]
    fn test_display() {
        let domain = TonDomain::parse("test.ton").unwrap();
        assert_eq!(format!("{}", domain), "test.ton");
    }

    #[test]
    fn test_unicode_domain() {
        // Unicode characters are allowed (except control chars)
        let domain = TonDomain::parse("cafe.ton").unwrap();
        assert_eq!(domain.as_str(), "cafe.ton");

        // Emoji (multi-byte UTF-8)
        let domain = TonDomain::parse("test.ton").unwrap();
        assert!(!domain.to_internal().is_empty());
    }
}
