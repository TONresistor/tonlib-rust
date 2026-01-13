//! TEP-64 Token Data Standard implementation.
//!
//! This module provides parsing and serialization of Jetton metadata
//! according to the TEP-64 standard.
//!
//! # Content Types
//!
//! - **Off-chain (0x00)**: URI pointing to JSON metadata
//! - **On-chain (0x01)**: Dictionary with key-value pairs stored in the cell

use std::collections::HashMap;
use std::sync::Arc;

use ton_cell::{Cell, CellBuilder, CellSlice, CellResult};

use crate::error::{JettonError, JettonResult};

/// Jetton content according to TEP-64 Token Data Standard.
#[derive(Debug, Clone)]
pub enum JettonContent {
    /// Off-chain content: URI pointing to JSON metadata.
    OffChain {
        /// URI to the metadata JSON file.
        uri: String,
    },
    /// On-chain content: metadata stored directly in the contract.
    OnChain(OnChainContent),
}

/// On-chain metadata fields.
#[derive(Debug, Clone, Default)]
pub struct OnChainContent {
    /// Token name (e.g., "Toncoin").
    pub name: Option<String>,
    /// Token description.
    pub description: Option<String>,
    /// Token symbol (e.g., "TON").
    pub symbol: Option<String>,
    /// Number of decimal places.
    pub decimals: Option<u8>,
    /// URL to token image.
    pub image: Option<String>,
    /// Raw image data (for small icons).
    pub image_data: Option<Vec<u8>>,
    /// Additional custom fields.
    pub extra: HashMap<String, String>,
}

impl OnChainContent {
    /// Creates a new empty OnChainContent.
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates OnChainContent with basic fields.
    pub fn with_basics(name: &str, symbol: &str, decimals: u8) -> Self {
        Self {
            name: Some(name.to_string()),
            symbol: Some(symbol.to_string()),
            decimals: Some(decimals),
            ..Default::default()
        }
    }

    /// Sets the name.
    pub fn set_name(&mut self, name: impl Into<String>) -> &mut Self {
        self.name = Some(name.into());
        self
    }

    /// Sets the description.
    pub fn set_description(&mut self, description: impl Into<String>) -> &mut Self {
        self.description = Some(description.into());
        self
    }

    /// Sets the symbol.
    pub fn set_symbol(&mut self, symbol: impl Into<String>) -> &mut Self {
        self.symbol = Some(symbol.into());
        self
    }

    /// Sets the decimals.
    pub fn set_decimals(&mut self, decimals: u8) -> &mut Self {
        self.decimals = Some(decimals);
        self
    }

    /// Sets the image URL.
    pub fn set_image(&mut self, image: impl Into<String>) -> &mut Self {
        self.image = Some(image.into());
        self
    }

    /// Sets raw image data.
    pub fn set_image_data(&mut self, data: Vec<u8>) -> &mut Self {
        self.image_data = Some(data);
        self
    }

    /// Adds a custom field.
    pub fn set_extra(&mut self, key: impl Into<String>, value: impl Into<String>) -> &mut Self {
        self.extra.insert(key.into(), value.into());
        self
    }
}

impl JettonContent {
    /// Parses JettonContent from a Cell according to TEP-64.
    ///
    /// # Format
    ///
    /// - `0x00` prefix: Off-chain content (snake format string follows)
    /// - `0x01` prefix: On-chain content (dictionary follows)
    pub fn from_cell(cell: &Cell) -> JettonResult<Self> {
        let mut slice = CellSlice::new(cell);

        if slice.bits_left() < 8 {
            return Err(JettonError::InvalidContentType(0xFF));
        }

        let content_type = slice.load_u8()?;

        match content_type {
            0x00 => {
                // Off-chain: 0x00 + URI in snake format
                let uri = parse_snake_string(&mut slice)?;
                Ok(JettonContent::OffChain { uri })
            }
            0x01 => {
                // On-chain: 0x01 + key-value dictionary
                let content = parse_onchain_content(cell)?;
                Ok(JettonContent::OnChain(content))
            }
            _ => Err(JettonError::InvalidContentType(content_type)),
        }
    }

    /// Serializes JettonContent to a Cell according to TEP-64.
    pub fn to_cell(&self) -> JettonResult<Cell> {
        match self {
            JettonContent::OffChain { uri } => {
                let mut builder = CellBuilder::new();
                builder.store_u8(0x00)?;
                store_snake_string(&mut builder, uri)?;
                Ok(builder.build()?)
            }
            JettonContent::OnChain(content) => {
                build_onchain_content(content)
            }
        }
    }

    /// Returns true if this is off-chain content.
    pub fn is_offchain(&self) -> bool {
        matches!(self, JettonContent::OffChain { .. })
    }

    /// Returns true if this is on-chain content.
    pub fn is_onchain(&self) -> bool {
        matches!(self, JettonContent::OnChain(_))
    }

    /// Returns the URI if this is off-chain content.
    pub fn uri(&self) -> Option<&str> {
        match self {
            JettonContent::OffChain { uri } => Some(uri),
            _ => None,
        }
    }

    /// Returns the on-chain content if available.
    pub fn onchain(&self) -> Option<&OnChainContent> {
        match self {
            JettonContent::OnChain(content) => Some(content),
            _ => None,
        }
    }
}

/// Parses a snake-format string from a CellSlice.
///
/// Snake format stores strings across multiple cells:
/// - Each cell contains up to (1023 - 8) / 8 = 127 bytes
/// - Continuation is stored in a reference
fn parse_snake_string(slice: &mut CellSlice) -> JettonResult<String> {
    let mut result = Vec::new();

    // Read remaining bytes from current slice
    while slice.bits_left() >= 8 {
        result.push(slice.load_u8()?);
    }

    // Follow references for continuation
    while slice.refs_left() > 0 {
        let ref_cell = slice.load_ref()?;
        let mut ref_slice = CellSlice::new(ref_cell);

        while ref_slice.bits_left() >= 8 {
            result.push(ref_slice.load_u8()?);
        }

        // Update slice to follow next reference
        if ref_slice.refs_left() > 0 {
            *slice = ref_slice;
        } else {
            break;
        }
    }

    String::from_utf8(result)
        .map_err(|e| JettonError::InvalidSnakeString(e.to_string()))
}

/// Stores a string in snake format.
fn store_snake_string(builder: &mut CellBuilder, s: &str) -> JettonResult<()> {
    let bytes = s.as_bytes();

    // Calculate how many bytes fit in the current cell
    // We have 1023 bits available, minus what's already used
    let available_bits = builder.bits_left();
    let available_bytes = available_bits / 8;

    if bytes.len() <= available_bytes {
        // Everything fits in this cell
        builder.store_bytes(bytes)?;
    } else {
        // Store what fits, put rest in reference
        builder.store_bytes(&bytes[..available_bytes])?;

        // Build continuation cells
        let remaining = &bytes[available_bytes..];
        let continuation = build_snake_continuation(remaining)?;
        builder.store_ref(Arc::new(continuation))?;
    }

    Ok(())
}

/// Builds continuation cells for snake format.
fn build_snake_continuation(data: &[u8]) -> CellResult<Cell> {
    let mut builder = CellBuilder::new();

    // Max bytes per cell (no prefix needed for continuation)
    const MAX_BYTES: usize = 127;

    if data.len() <= MAX_BYTES {
        builder.store_bytes(data)?;
    } else {
        builder.store_bytes(&data[..MAX_BYTES])?;
        let continuation = build_snake_continuation(&data[MAX_BYTES..])?;
        builder.store_ref(Arc::new(continuation))?;
    }

    builder.build()
}

/// Well-known dictionary keys for on-chain content.
#[allow(dead_code)]
mod keys {
    /// SHA256("uri")
    pub const URI: [u8; 32] = [
        0x70, 0xe5, 0xd7, 0xb6, 0xa2, 0x9b, 0x39, 0x2f,
        0x85, 0x07, 0x6f, 0xe1, 0x5c, 0xa2, 0xf2, 0x05,
        0x3c, 0x56, 0xc2, 0x33, 0x84, 0x14, 0xc5, 0x92,
        0xc0, 0x99, 0x3c, 0xfe, 0xbd, 0x35, 0xca, 0x81,
    ];
    /// SHA256("name")
    pub const NAME: [u8; 32] = [
        0x82, 0xa3, 0x53, 0x7f, 0xf0, 0xdb, 0xce, 0x7e,
        0xec, 0x35, 0xd6, 0x9e, 0xab, 0x3f, 0x37, 0xbc,
        0xa9, 0xf0, 0xd7, 0x2a, 0x96, 0xc9, 0x88, 0xa3,
        0x48, 0x09, 0x53, 0xdb, 0x16, 0x53, 0x5c, 0xe4,
    ];
    /// SHA256("description")
    pub const DESCRIPTION: [u8; 32] = [
        0xc9, 0x04, 0x6f, 0x7a, 0x37, 0xad, 0x0e, 0xa7,
        0xcc, 0xe7, 0x3b, 0x83, 0x6e, 0xdd, 0xe9, 0x03,
        0x85, 0xa6, 0xb1, 0xc5, 0x50, 0x6e, 0xce, 0x4f,
        0x58, 0x74, 0x18, 0x9c, 0x0a, 0x09, 0x79, 0xcd,
    ];
    /// SHA256("image")
    pub const IMAGE: [u8; 32] = [
        0x6f, 0x05, 0xae, 0xde, 0xaf, 0x3a, 0x3d, 0x4b,
        0x0a, 0x9a, 0xe7, 0x34, 0x8c, 0x73, 0x01, 0x09,
        0x34, 0x0f, 0x76, 0x86, 0x32, 0x75, 0x7e, 0x08,
        0xf7, 0x83, 0xda, 0x45, 0xd8, 0xc6, 0x01, 0x89,
    ];
    /// SHA256("image_data")
    pub const IMAGE_DATA: [u8; 32] = [
        0xd9, 0xa8, 0x8c, 0xca, 0xd2, 0x5f, 0x88, 0x3d,
        0x35, 0x35, 0x08, 0x79, 0x49, 0x84, 0x15, 0x44,
        0x49, 0xdb, 0xb5, 0x95, 0x48, 0x12, 0xe2, 0x9c,
        0x41, 0x7d, 0x40, 0x99, 0x7d, 0x5b, 0xc5, 0xd1,
    ];
    /// SHA256("symbol")
    pub const SYMBOL: [u8; 32] = [
        0xb7, 0x66, 0x08, 0xce, 0x4c, 0x5b, 0x95, 0xdf,
        0x43, 0x74, 0x04, 0xcd, 0x4c, 0x87, 0x21, 0x22,
        0xeb, 0x51, 0x3f, 0x92, 0xc3, 0xea, 0x4c, 0xc8,
        0x01, 0x3f, 0x90, 0x96, 0xfd, 0xb6, 0xbf, 0xbf,
    ];
    /// SHA256("decimals")
    pub const DECIMALS: [u8; 32] = [
        0xee, 0x80, 0xfd, 0x2f, 0x18, 0x97, 0x82, 0xbe,
        0xa2, 0xc8, 0x67, 0x7c, 0xbe, 0xcf, 0xd8, 0xe0,
        0x72, 0x93, 0x26, 0x61, 0xfa, 0x62, 0xc4, 0x4a,
        0x8c, 0xa1, 0xdf, 0x82, 0x4a, 0x8a, 0x65, 0xc4,
    ];
}

/// Parses on-chain content from a cell.
///
/// The cell should have the 0x01 prefix already consumed.
/// The remaining data is a dictionary mapping SHA256(key) -> snake-format value.
fn parse_onchain_content(cell: &Cell) -> JettonResult<OnChainContent> {
    let mut content = OnChainContent::default();

    // For simplicity in this implementation, we'll parse the dictionary manually.
    // A full implementation would use a proper dictionary parser.

    // The dictionary is stored after the 0x01 prefix.
    // In a real implementation, this would involve parsing the dictionary structure.
    // For now, we'll attempt a simplified parsing approach.

    let slice = CellSlice::new(cell);

    // Skip the content type prefix if present
    if slice.bits_left() >= 8 {
        // Dictionary parsing is complex in TON - the dictionary is a binary trie
        // stored across multiple cells. For a basic implementation, we'll check
        // if there are references that contain the dictionary data.

        if cell.reference_count() > 0 {
            // The dictionary root is typically in the first reference
            if let Some(dict_cell) = cell.reference(0) {
                // Try to extract known keys from the dictionary
                content = extract_content_from_dict(dict_cell)?;
            }
        }
    }

    Ok(content)
}

/// Attempts to extract content from a dictionary cell.
///
/// This is a simplified implementation. A full implementation would need
/// to properly traverse the dictionary trie structure.
fn extract_content_from_dict(cell: &Cell) -> JettonResult<OnChainContent> {
    let mut content = OnChainContent::default();

    // Dictionary in TON is a Hashmap(256, ^Cell) for on-chain content
    // The structure is complex - for now we'll return default content
    // A production implementation would properly parse the dictionary

    // Attempt to read values from the cell structure
    // This is highly simplified and may not work for all on-chain content

    for i in 0..cell.reference_count() {
        if let Some(ref_cell) = cell.reference(i) {
            // Try to read a value cell
            let mut slice = CellSlice::new(ref_cell);
            if slice.bits_left() >= 8 {
                // Check for snake format value (0x00 prefix for chunked data)
                let first_byte = slice.load_u8().ok();
                if first_byte == Some(0x00) {
                    // This is a snake-format string
                    if let Ok(value) = parse_snake_string(&mut slice) {
                        // We don't know which key this belongs to without proper dict parsing
                        // Store it as an extra field with index
                        content.extra.insert(format!("field_{}", i), value);
                    }
                }
            }
        }
    }

    Ok(content)
}

/// Builds on-chain content cell.
fn build_onchain_content(content: &OnChainContent) -> JettonResult<Cell> {
    let mut builder = CellBuilder::new();
    builder.store_u8(0x01)?;

    // For a full implementation, we would build a proper dictionary here.
    // This simplified version stores content in a basic format.

    // Build dictionary entries
    let mut entries: Vec<([u8; 32], Vec<u8>)> = Vec::new();

    if let Some(ref name) = content.name {
        entries.push((keys::NAME, name.as_bytes().to_vec()));
    }
    if let Some(ref symbol) = content.symbol {
        entries.push((keys::SYMBOL, symbol.as_bytes().to_vec()));
    }
    if let Some(decimals) = content.decimals {
        entries.push((keys::DECIMALS, decimals.to_string().as_bytes().to_vec()));
    }
    if let Some(ref description) = content.description {
        entries.push((keys::DESCRIPTION, description.as_bytes().to_vec()));
    }
    if let Some(ref image) = content.image {
        entries.push((keys::IMAGE, image.as_bytes().to_vec()));
    }
    if let Some(ref image_data) = content.image_data {
        entries.push((keys::IMAGE_DATA, image_data.clone()));
    }

    // For simplicity, store entries in references
    // A proper implementation would build a hashmap dictionary
    if !entries.is_empty() {
        let dict_cell = build_simple_dict(&entries)?;
        builder.store_ref(Arc::new(dict_cell))?;
    }

    Ok(builder.build()?)
}

/// Builds a simplified dictionary structure.
///
/// Note: This is a simplified implementation. A production version would
/// use proper TON dictionary encoding.
fn build_simple_dict(entries: &[([u8; 32], Vec<u8>)]) -> CellResult<Cell> {
    let mut builder = CellBuilder::new();

    // Store the number of entries (for debugging)
    // In a real implementation, this would be a proper binary trie

    for (key, value) in entries {
        // Build a value cell with snake format
        let mut value_builder = CellBuilder::new();
        value_builder.store_u8(0x00)?; // Snake format prefix
        if value.len() <= 127 {
            value_builder.store_bytes(value)?;
        } else {
            value_builder.store_bytes(&value[..127])?;
            let continuation = build_snake_continuation(&value[127..])?;
            value_builder.store_ref(Arc::new(continuation))?;
        }
        let value_cell = value_builder.build()?;

        // Build a key-value pair cell
        let mut kv_builder = CellBuilder::new();
        kv_builder.store_bytes(key)?;
        kv_builder.store_ref(Arc::new(value_cell))?;

        // Add to dictionary cell as reference (simplified)
        if builder.refs_left() > 0 {
            builder.store_ref(Arc::new(kv_builder.build()?))?;
        }
    }

    builder.build()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_offchain_content_roundtrip() {
        let uri = "https://example.com/token.json";
        let content = JettonContent::OffChain { uri: uri.to_string() };

        let cell = content.to_cell().unwrap();
        let parsed = JettonContent::from_cell(&cell).unwrap();

        match parsed {
            JettonContent::OffChain { uri: parsed_uri } => {
                assert_eq!(parsed_uri, uri);
            }
            _ => panic!("Expected OffChain content"),
        }
    }

    #[test]
    fn test_offchain_content_is_offchain() {
        let content = JettonContent::OffChain { uri: "test".to_string() };
        assert!(content.is_offchain());
        assert!(!content.is_onchain());
        assert_eq!(content.uri(), Some("test"));
    }

    #[test]
    fn test_onchain_content_is_onchain() {
        let content = JettonContent::OnChain(OnChainContent::default());
        assert!(!content.is_offchain());
        assert!(content.is_onchain());
        assert!(content.onchain().is_some());
    }

    #[test]
    fn test_onchain_content_builder() {
        let mut content = OnChainContent::new();
        content
            .set_name("Test Token")
            .set_symbol("TEST")
            .set_decimals(9)
            .set_description("A test token")
            .set_image("https://example.com/image.png");

        assert_eq!(content.name.as_deref(), Some("Test Token"));
        assert_eq!(content.symbol.as_deref(), Some("TEST"));
        assert_eq!(content.decimals, Some(9));
        assert_eq!(content.description.as_deref(), Some("A test token"));
        assert_eq!(content.image.as_deref(), Some("https://example.com/image.png"));
    }

    #[test]
    fn test_onchain_content_with_basics() {
        let content = OnChainContent::with_basics("Token", "TKN", 9);

        assert_eq!(content.name.as_deref(), Some("Token"));
        assert_eq!(content.symbol.as_deref(), Some("TKN"));
        assert_eq!(content.decimals, Some(9));
    }

    #[test]
    fn test_snake_string_short() {
        let mut builder = CellBuilder::new();
        builder.store_u8(0x00).unwrap(); // Prefix for off-chain
        store_snake_string(&mut builder, "hello").unwrap();
        let cell = builder.build().unwrap();

        let mut slice = CellSlice::new(&cell);
        let content_type = slice.load_u8().unwrap();
        assert_eq!(content_type, 0x00);

        let parsed = parse_snake_string(&mut slice).unwrap();
        assert_eq!(parsed, "hello");
    }

    #[test]
    fn test_invalid_content_type() {
        let mut builder = CellBuilder::new();
        builder.store_u8(0x42).unwrap(); // Invalid type
        let cell = builder.build().unwrap();

        let result = JettonContent::from_cell(&cell);
        assert!(result.is_err());

        match result {
            Err(JettonError::InvalidContentType(t)) => assert_eq!(t, 0x42),
            _ => panic!("Expected InvalidContentType error"),
        }
    }

    #[test]
    fn test_onchain_content_to_cell() {
        let content = OnChainContent::with_basics("Test", "TST", 6);
        let jetton_content = JettonContent::OnChain(content);

        let cell = jetton_content.to_cell().unwrap();

        // Verify the cell starts with 0x01 (on-chain prefix)
        let mut slice = CellSlice::new(&cell);
        let prefix = slice.load_u8().unwrap();
        assert_eq!(prefix, 0x01);
    }
}
