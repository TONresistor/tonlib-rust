//! TL (Type Language) structures and schema IDs for TON Storage protocol.
//!
//! This module defines the TL schemas used for communication between storage
//! nodes and clients. The storage protocol uses these messages for:
//!
//! - Querying torrent information
//! - Downloading pieces with proofs
//! - Pinging storage nodes
//! - Provider discovery and node information
//! - Upload sessions and chunk transfers
//!
//! # TL Schemas
//!
//! ## Download Protocol
//! ```text
//! storage.getTorrentInfo bag_id:int256 = storage.TorrentInfo;
//! storage.getPiece bag_id:int256 piece_id:int = storage.Piece;
//! storage.ping random_id:long = storage.Pong;
//!
//! storage.torrentInfo chunk_size:int file_size:long root_hash:int256
//!                     header_size:long header_hash:int256 description:string
//!                     = storage.TorrentInfo;
//! storage.piece proof:bytes data:bytes = storage.Piece;
//! storage.pong random_id:long = storage.Pong;
//! ```
//!
//! ## Upload Protocol (Phase 2)
//! ```text
//! storage.address ip:int port:int = storage.Address;
//!
//! storage.nodeInfo provider_id:int256 address:storage.address version:int flags:int
//!                  available_space:long used_space:long bags_count:int max_chunk_size:int
//!                  = storage.NodeInfo;
//!
//! storage.nodeValue node_info:storage.NodeInfo signature:bytes timestamp:long
//!                  = storage.NodeValue;
//!
//! storage.uploadSessionInfo session_id:int256 bag_id:int256 total_size:long
//!                           uploaded_size:long progress:int peers_count:int
//!                           state:int = storage.UploadSessionInfo;
//!
//! storage.chunkUploadRequest session_id:int256 chunk_id:int chunk_data:bytes
//!                            crc32:int = storage.ChunkUploadRequest;
//!
//! storage.chunkUploadResponse session_id:int256 chunk_id:int received_bytes:long
//!                             status:int = storage.ChunkUploadResponse;
//!
//! storage.providerListRequest bag_id:int256 max_peers:int = storage.ProviderListRequest;
//!
//! storage.providerListResponse providers:(vector storage.NodeInfo) timestamp:long
//!                              = storage.ProviderListResponse;
//! ```

use crate::bag::{BagId, TorrentInfo};
use crate::error::{StorageError, StorageResult};
use crate::types::StoragePiece;
use std::net::Ipv4Addr;

// ============================================================================
// TL Schema IDs
// ============================================================================

/// TL schema ID for `storage.getTorrentInfo`
pub const TL_STORAGE_GET_TORRENT_INFO: u32 = 0x6b5ea2f1;

/// TL schema ID for `storage.getPiece`
pub const TL_STORAGE_GET_PIECE: u32 = 0x2a1c4b7d;

/// TL schema ID for `storage.ping`
pub const TL_STORAGE_PING: u32 = 0x8e7c9d3a;

/// TL schema ID for `storage.torrentInfo` (response)
pub const TL_STORAGE_TORRENT_INFO: u32 = 0x4d8f2e6c;

/// TL schema ID for `storage.piece` (response)
pub const TL_STORAGE_PIECE: u32 = 0x9a3b5c7e;

/// TL schema ID for `storage.pong` (response)
pub const TL_STORAGE_PONG: u32 = 0x1f5e8d2b;

/// TL schema ID for `storage.addProvider`
pub const TL_STORAGE_ADD_PROVIDER: u32 = 0x3c7a9e5f;

/// TL schema ID for `storage.getProviders`
pub const TL_STORAGE_GET_PROVIDERS: u32 = 0x5b4d6c8a;

/// TL schema ID for `storage.providers` (response)
pub const TL_STORAGE_PROVIDERS: u32 = 0x7e2f4a9c;

/// TL schema ID for `storage.updateState`
pub const TL_STORAGE_UPDATE_STATE: u32 = 0x8c1d3e5a;

/// TL schema ID for `storage.state` (response)
pub const TL_STORAGE_STATE: u32 = 0xa5b7c9d1;

// ============================================================================
// TL Schema IDs - Upload Protocol (Phase 2)
// ============================================================================

/// TL schema ID for `storage.address`
pub const TL_STORAGE_ADDRESS: u32 = 0x1a2b3c02;

/// TL schema ID for `storage.nodeInfo`
pub const TL_STORAGE_NODE_INFO: u32 = 0x1a2b3c01;

/// TL schema ID for `storage.nodeValue`
pub const TL_STORAGE_NODE_VALUE: u32 = 0x1a2b3c03;

/// TL schema ID for `storage.uploadSessionInfo`
pub const TL_STORAGE_UPLOAD_SESSION_INFO: u32 = 0x1a2b3c04;

/// TL schema ID for `storage.chunkUploadRequest`
pub const TL_STORAGE_CHUNK_UPLOAD_REQUEST: u32 = 0x1a2b3c05;

/// TL schema ID for `storage.chunkUploadResponse`
pub const TL_STORAGE_CHUNK_UPLOAD_RESPONSE: u32 = 0x1a2b3c06;

/// TL schema ID for `storage.providerListRequest`
pub const TL_STORAGE_PROVIDER_LIST_REQUEST: u32 = 0x1a2b3c07;

/// TL schema ID for `storage.providerListResponse`
pub const TL_STORAGE_PROVIDER_LIST_RESPONSE: u32 = 0x1a2b3c08;

// ============================================================================
// TL Reader/Writer Helpers
// ============================================================================

/// Simple TL reader for parsing binary data.
#[derive(Debug)]
pub struct TlReader<'a> {
    data: &'a [u8],
    offset: usize,
}

impl<'a> TlReader<'a> {
    /// Creates a new TL reader.
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, offset: 0 }
    }

    /// Returns the remaining data.
    pub fn remaining(&self) -> &'a [u8] {
        &self.data[self.offset..]
    }

    /// Returns the number of bytes remaining.
    pub fn remaining_len(&self) -> usize {
        self.data.len() - self.offset
    }

    /// Reads a u8.
    pub fn read_u8(&mut self) -> StorageResult<u8> {
        if self.offset >= self.data.len() {
            return Err(StorageError::DeserializationError(
                "Unexpected end of data reading u8".into(),
            ));
        }
        let value = self.data[self.offset];
        self.offset += 1;
        Ok(value)
    }

    /// Reads a u16 (little-endian).
    pub fn read_u16(&mut self) -> StorageResult<u16> {
        if self.offset + 2 > self.data.len() {
            return Err(StorageError::DeserializationError(
                "Unexpected end of data reading u16".into(),
            ));
        }
        let value = u16::from_le_bytes(
            self.data[self.offset..self.offset + 2]
                .try_into()
                .map_err(|_| StorageError::DeserializationError("Invalid u16".into()))?,
        );
        self.offset += 2;
        Ok(value)
    }

    /// Reads a u32 (little-endian).
    pub fn read_u32(&mut self) -> StorageResult<u32> {
        if self.offset + 4 > self.data.len() {
            return Err(StorageError::DeserializationError(
                "Unexpected end of data reading u32".into(),
            ));
        }
        let value = u32::from_le_bytes(
            self.data[self.offset..self.offset + 4]
                .try_into()
                .map_err(|_| StorageError::DeserializationError("Invalid u32".into()))?,
        );
        self.offset += 4;
        Ok(value)
    }

    /// Reads an i32 (little-endian).
    pub fn read_i32(&mut self) -> StorageResult<i32> {
        if self.offset + 4 > self.data.len() {
            return Err(StorageError::DeserializationError(
                "Unexpected end of data reading i32".into(),
            ));
        }
        let value = i32::from_le_bytes(
            self.data[self.offset..self.offset + 4]
                .try_into()
                .map_err(|_| StorageError::DeserializationError("Invalid i32".into()))?,
        );
        self.offset += 4;
        Ok(value)
    }

    /// Reads a u64 (little-endian).
    pub fn read_u64(&mut self) -> StorageResult<u64> {
        if self.offset + 8 > self.data.len() {
            return Err(StorageError::DeserializationError(
                "Unexpected end of data reading u64".into(),
            ));
        }
        let value = u64::from_le_bytes(
            self.data[self.offset..self.offset + 8]
                .try_into()
                .map_err(|_| StorageError::DeserializationError("Invalid u64".into()))?,
        );
        self.offset += 8;
        Ok(value)
    }

    /// Reads an i64 (little-endian).
    pub fn read_i64(&mut self) -> StorageResult<i64> {
        if self.offset + 8 > self.data.len() {
            return Err(StorageError::DeserializationError(
                "Unexpected end of data reading i64".into(),
            ));
        }
        let value = i64::from_le_bytes(
            self.data[self.offset..self.offset + 8]
                .try_into()
                .map_err(|_| StorageError::DeserializationError("Invalid i64".into()))?,
        );
        self.offset += 8;
        Ok(value)
    }

    /// Reads a 256-bit integer (32 bytes).
    pub fn read_int256(&mut self) -> StorageResult<[u8; 32]> {
        if self.offset + 32 > self.data.len() {
            return Err(StorageError::DeserializationError(
                "Unexpected end of data reading int256".into(),
            ));
        }
        let value: [u8; 32] = self.data[self.offset..self.offset + 32]
            .try_into()
            .map_err(|_| StorageError::DeserializationError("Invalid int256".into()))?;
        self.offset += 32;
        Ok(value)
    }

    /// Reads a TL bytes field.
    ///
    /// TL bytes are length-prefixed:
    /// - If first byte < 254: length is first byte, followed by data, padded to 4 bytes
    /// - If first byte == 254: length is next 3 bytes (little-endian), followed by data, padded
    pub fn read_bytes(&mut self) -> StorageResult<Vec<u8>> {
        if self.offset >= self.data.len() {
            return Err(StorageError::DeserializationError(
                "Unexpected end of data reading bytes length".into(),
            ));
        }

        let first_byte = self.data[self.offset];
        self.offset += 1;

        let len = if first_byte < 254 {
            first_byte as usize
        } else if first_byte == 254 {
            if self.offset + 3 > self.data.len() {
                return Err(StorageError::DeserializationError(
                    "Unexpected end of data reading bytes length (254)".into(),
                ));
            }
            let l = self.data[self.offset] as usize
                | ((self.data[self.offset + 1] as usize) << 8)
                | ((self.data[self.offset + 2] as usize) << 16);
            self.offset += 3;
            l
        } else {
            return Err(StorageError::DeserializationError(
                "Invalid bytes length prefix (255 not supported)".into(),
            ));
        };

        if self.offset + len > self.data.len() {
            return Err(StorageError::DeserializationError(
                "Unexpected end of data reading bytes content".into(),
            ));
        }

        let value = self.data[self.offset..self.offset + len].to_vec();
        self.offset += len;

        // Skip padding to 4-byte alignment
        let total = if first_byte < 254 { 1 + len } else { 4 + len };
        let padding = (4 - (total % 4)) % 4;
        self.offset += padding;

        Ok(value)
    }

    /// Reads a TL string field.
    pub fn read_string(&mut self) -> StorageResult<String> {
        let bytes = self.read_bytes()?;
        String::from_utf8(bytes).map_err(|_| {
            StorageError::DeserializationError("Invalid UTF-8 in string".into())
        })
    }
}

/// Simple TL writer for serializing binary data.
#[derive(Debug, Default)]
pub struct TlWriter {
    data: Vec<u8>,
}

impl TlWriter {
    /// Creates a new TL writer.
    pub fn new() -> Self {
        Self { data: Vec::new() }
    }

    /// Creates a new TL writer with preallocated capacity.
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            data: Vec::with_capacity(capacity),
        }
    }

    /// Returns the written data.
    pub fn finish(self) -> Vec<u8> {
        self.data
    }

    /// Returns a reference to the current data.
    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }

    /// Writes raw bytes.
    pub fn write_raw(&mut self, data: &[u8]) {
        self.data.extend_from_slice(data);
    }

    /// Writes a u8.
    pub fn write_u8(&mut self, value: u8) {
        self.data.push(value);
    }

    /// Writes a u16 (little-endian).
    pub fn write_u16(&mut self, value: u16) {
        self.data.extend_from_slice(&value.to_le_bytes());
    }

    /// Writes a u32 (little-endian).
    pub fn write_u32(&mut self, value: u32) {
        self.data.extend_from_slice(&value.to_le_bytes());
    }

    /// Writes an i32 (little-endian).
    pub fn write_i32(&mut self, value: i32) {
        self.data.extend_from_slice(&value.to_le_bytes());
    }

    /// Writes a u64 (little-endian).
    pub fn write_u64(&mut self, value: u64) {
        self.data.extend_from_slice(&value.to_le_bytes());
    }

    /// Writes an i64 (little-endian).
    pub fn write_i64(&mut self, value: i64) {
        self.data.extend_from_slice(&value.to_le_bytes());
    }

    /// Writes a 256-bit integer (32 bytes).
    pub fn write_int256(&mut self, value: &[u8; 32]) {
        self.data.extend_from_slice(value);
    }

    /// Writes a TL bytes field.
    pub fn write_bytes(&mut self, value: &[u8]) {
        let len = value.len();

        if len < 254 {
            self.data.push(len as u8);
        } else {
            self.data.push(254);
            self.data.push((len & 0xff) as u8);
            self.data.push(((len >> 8) & 0xff) as u8);
            self.data.push(((len >> 16) & 0xff) as u8);
        }

        self.data.extend_from_slice(value);

        // Add padding to 4-byte alignment
        let total = if len < 254 { 1 + len } else { 4 + len };
        let padding = (4 - (total % 4)) % 4;
        for _ in 0..padding {
            self.data.push(0);
        }
    }

    /// Writes a TL string field.
    pub fn write_string(&mut self, value: &str) {
        self.write_bytes(value.as_bytes());
    }
}

// ============================================================================
// Upload Protocol Data Structures
// ============================================================================

/// Network address structure: `storage.address ip:int port:int`
///
/// Represents a network endpoint for a storage provider.
#[derive(Debug, Clone)]
pub struct StorageAddress {
    /// IPv4 address as a 32-bit integer (network byte order).
    pub ip: u32,
    /// Network port number.
    pub port: u16,
}

impl StorageAddress {
    /// Creates a new storage address.
    pub fn new(ip: u32, port: u16) -> Self {
        Self { ip, port }
    }

    /// Creates a storage address from an IPv4 address and port.
    pub fn from_ipv4(ip: Ipv4Addr, port: u16) -> Self {
        Self {
            ip: u32::from(ip),
            port,
        }
    }

    /// Converts to IPv4 address.
    pub fn to_ipv4(&self) -> Ipv4Addr {
        Ipv4Addr::from(self.ip)
    }

    /// Serializes to TL format (without schema ID).
    pub fn to_tl_data(&self) -> Vec<u8> {
        let mut writer = TlWriter::with_capacity(8);
        writer.write_u32(self.ip);
        writer.write_u16(self.port);
        writer.finish()
    }

    /// Deserializes from TL format (without schema ID).
    pub fn from_tl_data(data: &[u8]) -> StorageResult<Self> {
        if data.len() < 6 {
            return Err(StorageError::DeserializationError(
                "StorageAddress data too short".into(),
            ));
        }

        let ip = u32::from_le_bytes(
            data[0..4]
                .try_into()
                .map_err(|_| StorageError::DeserializationError("Invalid ip".into()))?,
        );

        let port = u16::from_le_bytes(
            data[4..6]
                .try_into()
                .map_err(|_| StorageError::DeserializationError("Invalid port".into()))?,
        );

        Ok(Self { ip, port })
    }
}

/// Node information structure: `storage.nodeInfo provider_id:int256 address:storage.address ...`
///
/// Contains information about a storage provider node.
#[derive(Debug, Clone)]
pub struct StorageNodeInfo {
    /// Provider's unique ID (256-bit).
    pub provider_id: [u8; 32],
    /// Network address of the provider.
    pub address: StorageAddress,
    /// Protocol version.
    pub version: u32,
    /// Flags for provider capabilities.
    pub flags: u32,
    /// Available storage space in bytes.
    pub available_space: u64,
    /// Currently used storage space in bytes.
    pub used_space: u64,
    /// Number of bags stored by this provider.
    pub bags_count: u32,
    /// Maximum chunk size accepted by this provider.
    pub max_chunk_size: u32,
}

impl StorageNodeInfo {
    /// Creates a new node info.
    pub fn new(
        provider_id: [u8; 32],
        address: StorageAddress,
        version: u32,
        available_space: u64,
    ) -> Self {
        Self {
            provider_id,
            address,
            version,
            flags: 0,
            available_space,
            used_space: 0,
            bags_count: 0,
            max_chunk_size: 131072, // 128 KB default
        }
    }

    /// Serializes to TL format (with schema ID).
    pub fn serialize(&self) -> Vec<u8> {
        let mut writer = TlWriter::with_capacity(128);
        writer.write_u32(TL_STORAGE_NODE_INFO);
        writer.write_int256(&self.provider_id);
        writer.write_u32(self.address.ip);
        writer.write_u32(self.address.port as u32); // port as u32 for alignment
        writer.write_u32(self.version);
        writer.write_u32(self.flags);
        writer.write_u64(self.available_space);
        writer.write_u64(self.used_space);
        writer.write_u32(self.bags_count);
        writer.write_u32(self.max_chunk_size);
        writer.finish()
    }

    /// Deserializes from TL format (without schema ID).
    pub fn deserialize(data: &[u8]) -> StorageResult<Self> {
        if data.len() < 68 {
            return Err(StorageError::DeserializationError(
                "StorageNodeInfo data too short".into(),
            ));
        }

        let provider_id: [u8; 32] = data[0..32]
            .try_into()
            .map_err(|_| StorageError::DeserializationError("Invalid provider_id".into()))?;

        let ip = u32::from_le_bytes(
            data[32..36]
                .try_into()
                .map_err(|_| StorageError::DeserializationError("Invalid ip".into()))?,
        );

        let port = u32::from_le_bytes(
            data[36..40]
                .try_into()
                .map_err(|_| StorageError::DeserializationError("Invalid port".into()))?,
        ) as u16;

        let version = u32::from_le_bytes(
            data[40..44]
                .try_into()
                .map_err(|_| StorageError::DeserializationError("Invalid version".into()))?,
        );

        let flags = u32::from_le_bytes(
            data[44..48]
                .try_into()
                .map_err(|_| StorageError::DeserializationError("Invalid flags".into()))?,
        );

        let available_space = u64::from_le_bytes(
            data[48..56]
                .try_into()
                .map_err(|_| StorageError::DeserializationError("Invalid available_space".into()))?,
        );

        let used_space = u64::from_le_bytes(
            data[56..64]
                .try_into()
                .map_err(|_| StorageError::DeserializationError("Invalid used_space".into()))?,
        );

        let bags_count = u32::from_le_bytes(
            data[64..68]
                .try_into()
                .map_err(|_| StorageError::DeserializationError("Invalid bags_count".into()))?,
        );

        let max_chunk_size = u32::from_le_bytes(
            data[68..72]
                .try_into()
                .map_err(|_| StorageError::DeserializationError("Invalid max_chunk_size".into()))?,
        );

        Ok(Self {
            provider_id,
            address: StorageAddress::new(ip, port),
            version,
            flags,
            available_space,
            used_space,
            bags_count,
            max_chunk_size,
        })
    }
}

/// Node value structure: `storage.nodeValue node_info:storage.NodeInfo signature:bytes timestamp:long`
///
/// Signed node information for upload protocol announcements (TL format).
/// This is distinct from the DHT `StorageNodeValue` which uses a different format.
#[derive(Debug, Clone)]
pub struct StorageNodeValueTL {
    /// The node information being signed.
    pub node_info: StorageNodeInfo,
    /// Digital signature (Ed25519).
    pub signature: Vec<u8>,
    /// Timestamp when this value was created.
    pub timestamp: i64,
}

impl StorageNodeValueTL {
    /// Creates a new signed node value.
    pub fn new(node_info: StorageNodeInfo, signature: Vec<u8>, timestamp: i64) -> Self {
        Self {
            node_info,
            signature,
            timestamp,
        }
    }

    /// Serializes to TL format (with schema ID).
    pub fn serialize(&self) -> Vec<u8> {
        let node_info_data = self.node_info.serialize();
        let mut writer = TlWriter::with_capacity(200 + self.signature.len());

        writer.write_u32(TL_STORAGE_NODE_VALUE);
        // Write the node_info data (with its schema ID)
        writer.write_raw(&node_info_data);
        writer.write_bytes(&self.signature);
        writer.write_i64(self.timestamp);

        writer.finish()
    }

    /// Deserializes from TL format (without schema ID).
    pub fn deserialize(data: &[u8]) -> StorageResult<Self> {
        let mut reader = TlReader::new(data);

        // Read node_info (with schema ID prefix)
        let schema = reader.read_u32()?;
        if schema != TL_STORAGE_NODE_INFO {
            return Err(StorageError::DeserializationError(
                "Invalid schema ID for nodeInfo".into(),
            ));
        }

        let node_info = StorageNodeInfo::deserialize(reader.remaining())?;

        // Advance reader past the node_info
        // 4 (schema) + 32 (provider_id) + 4 (ip) + 4 (port as u32) + 4 (version) + 4 (flags) + 8 (available_space) + 8 (used_space) + 4 (bags_count) + 4 (max_chunk_size) = 76
        reader.offset += 72; // skip 72 bytes of node_info data (already read 4 bytes for schema, so 76 - 4 = 72)

        let signature = reader.read_bytes()?;
        let timestamp = reader.read_i64()?;

        Ok(Self {
            node_info,
            signature,
            timestamp,
        })
    }
}

/// Upload session information: `storage.uploadSessionInfo session_id:int256 bag_id:int256 ...`
///
/// Tracks the state of an ongoing upload session.
#[derive(Debug, Clone)]
pub struct StorageUploadSessionInfo {
    /// Unique session ID (256-bit).
    pub session_id: [u8; 32],
    /// Bag being uploaded (256-bit).
    pub bag_id: [u8; 32],
    /// Total size of the bag in bytes.
    pub total_size: u64,
    /// Amount uploaded so far in bytes.
    pub uploaded_size: u64,
    /// Progress percentage (0-100).
    pub progress: u32,
    /// Number of peers in this session.
    pub peers_count: u32,
    /// Current session state (0=idle, 1=uploading, 2=paused, 3=completed, 4=error).
    pub state: u32,
}

impl StorageUploadSessionInfo {
    /// Creates a new upload session info.
    pub fn new(session_id: [u8; 32], bag_id: [u8; 32], total_size: u64) -> Self {
        Self {
            session_id,
            bag_id,
            total_size,
            uploaded_size: 0,
            progress: 0,
            peers_count: 0,
            state: 0,
        }
    }

    /// Serializes to TL format (with schema ID).
    pub fn serialize(&self) -> Vec<u8> {
        let mut writer = TlWriter::with_capacity(100);
        writer.write_u32(TL_STORAGE_UPLOAD_SESSION_INFO);
        writer.write_int256(&self.session_id);
        writer.write_int256(&self.bag_id);
        writer.write_u64(self.total_size);
        writer.write_u64(self.uploaded_size);
        writer.write_u32(self.progress);
        writer.write_u32(self.peers_count);
        writer.write_u32(self.state);
        writer.finish()
    }

    /// Deserializes from TL format (without schema ID).
    pub fn deserialize(data: &[u8]) -> StorageResult<Self> {
        if data.len() < 88 {
            return Err(StorageError::DeserializationError(
                "StorageUploadSessionInfo data too short".into(),
            ));
        }

        let session_id: [u8; 32] = data[0..32]
            .try_into()
            .map_err(|_| StorageError::DeserializationError("Invalid session_id".into()))?;

        let bag_id: [u8; 32] = data[32..64]
            .try_into()
            .map_err(|_| StorageError::DeserializationError("Invalid bag_id".into()))?;

        let total_size = u64::from_le_bytes(
            data[64..72]
                .try_into()
                .map_err(|_| StorageError::DeserializationError("Invalid total_size".into()))?,
        );

        let uploaded_size = u64::from_le_bytes(
            data[72..80]
                .try_into()
                .map_err(|_| StorageError::DeserializationError("Invalid uploaded_size".into()))?,
        );

        let progress = u32::from_le_bytes(
            data[80..84]
                .try_into()
                .map_err(|_| StorageError::DeserializationError("Invalid progress".into()))?,
        );

        let peers_count = u32::from_le_bytes(
            data[84..88]
                .try_into()
                .map_err(|_| StorageError::DeserializationError("Invalid peers_count".into()))?,
        );

        let state = u32::from_le_bytes(
            data[88..92]
                .try_into()
                .map_err(|_| StorageError::DeserializationError("Invalid state".into()))?,
        );

        Ok(Self {
            session_id,
            bag_id,
            total_size,
            uploaded_size,
            progress,
            peers_count,
            state,
        })
    }
}

/// Chunk upload request: `storage.chunkUploadRequest session_id:int256 chunk_id:int chunk_data:bytes crc32:int`
///
/// Request to upload a single chunk to a provider.
#[derive(Debug, Clone)]
pub struct StorageChunkUploadRequest {
    /// Session ID this chunk belongs to.
    pub session_id: [u8; 32],
    /// Chunk index within the session.
    pub chunk_id: u32,
    /// The chunk data to upload.
    pub chunk_data: Vec<u8>,
    /// CRC32 checksum for integrity verification.
    pub crc32: u32,
}

impl StorageChunkUploadRequest {
    /// Creates a new chunk upload request.
    pub fn new(session_id: [u8; 32], chunk_id: u32, chunk_data: Vec<u8>, crc32: u32) -> Self {
        Self {
            session_id,
            chunk_id,
            chunk_data,
            crc32,
        }
    }

    /// Serializes to TL format (with schema ID).
    pub fn serialize(&self) -> Vec<u8> {
        let mut writer = TlWriter::with_capacity(56 + self.chunk_data.len());
        writer.write_u32(TL_STORAGE_CHUNK_UPLOAD_REQUEST);
        writer.write_int256(&self.session_id);
        writer.write_u32(self.chunk_id);
        writer.write_bytes(&self.chunk_data);
        writer.write_u32(self.crc32);
        writer.finish()
    }

    /// Deserializes from TL format (without schema ID).
    pub fn deserialize(data: &[u8]) -> StorageResult<Self> {
        let mut reader = TlReader::new(data);

        let session_id = reader.read_int256()?;
        let chunk_id = reader.read_u32()?;
        let chunk_data = reader.read_bytes()?;
        let crc32 = reader.read_u32()?;

        Ok(Self {
            session_id,
            chunk_id,
            chunk_data,
            crc32,
        })
    }
}

/// Chunk upload response: `storage.chunkUploadResponse session_id:int256 chunk_id:int received_bytes:long status:int`
///
/// Response after uploading a chunk.
#[derive(Debug, Clone)]
pub struct StorageChunkUploadResponse {
    /// Session ID of the upload.
    pub session_id: [u8; 32],
    /// Chunk ID that was uploaded.
    pub chunk_id: u32,
    /// Number of bytes received by the provider.
    pub received_bytes: u64,
    /// Status code (0=success, 1=invalid_crc, 2=storage_full, 3=error).
    pub status: u32,
}

impl StorageChunkUploadResponse {
    /// Creates a new chunk upload response.
    pub fn new(session_id: [u8; 32], chunk_id: u32, received_bytes: u64, status: u32) -> Self {
        Self {
            session_id,
            chunk_id,
            received_bytes,
            status,
        }
    }

    /// Serializes to TL format (with schema ID).
    pub fn serialize(&self) -> Vec<u8> {
        let mut writer = TlWriter::with_capacity(56);
        writer.write_u32(TL_STORAGE_CHUNK_UPLOAD_RESPONSE);
        writer.write_int256(&self.session_id);
        writer.write_u32(self.chunk_id);
        writer.write_u64(self.received_bytes);
        writer.write_u32(self.status);
        writer.finish()
    }

    /// Deserializes from TL format (without schema ID).
    pub fn deserialize(data: &[u8]) -> StorageResult<Self> {
        if data.len() < 48 {
            return Err(StorageError::DeserializationError(
                "StorageChunkUploadResponse data too short".into(),
            ));
        }

        let session_id: [u8; 32] = data[0..32]
            .try_into()
            .map_err(|_| StorageError::DeserializationError("Invalid session_id".into()))?;

        let chunk_id = u32::from_le_bytes(
            data[32..36]
                .try_into()
                .map_err(|_| StorageError::DeserializationError("Invalid chunk_id".into()))?,
        );

        let received_bytes = u64::from_le_bytes(
            data[36..44]
                .try_into()
                .map_err(|_| StorageError::DeserializationError("Invalid received_bytes".into()))?,
        );

        let status = u32::from_le_bytes(
            data[44..48]
                .try_into()
                .map_err(|_| StorageError::DeserializationError("Invalid status".into()))?,
        );

        Ok(Self {
            session_id,
            chunk_id,
            received_bytes,
            status,
        })
    }
}

/// Provider list request: `storage.providerListRequest bag_id:int256 max_peers:int`
///
/// Request to discover providers for a bag.
#[derive(Debug, Clone)]
pub struct StorageProviderListRequest {
    /// Bag ID to find providers for.
    pub bag_id: [u8; 32],
    /// Maximum number of providers to return.
    pub max_peers: u32,
}

impl StorageProviderListRequest {
    /// Creates a new provider list request.
    pub fn new(bag_id: [u8; 32], max_peers: u32) -> Self {
        Self { bag_id, max_peers }
    }

    /// Serializes to TL format (with schema ID).
    pub fn serialize(&self) -> Vec<u8> {
        let mut writer = TlWriter::with_capacity(40);
        writer.write_u32(TL_STORAGE_PROVIDER_LIST_REQUEST);
        writer.write_int256(&self.bag_id);
        writer.write_u32(self.max_peers);
        writer.finish()
    }

    /// Deserializes from TL format (without schema ID).
    pub fn deserialize(data: &[u8]) -> StorageResult<Self> {
        if data.len() < 36 {
            return Err(StorageError::DeserializationError(
                "StorageProviderListRequest data too short".into(),
            ));
        }

        let bag_id: [u8; 32] = data[0..32]
            .try_into()
            .map_err(|_| StorageError::DeserializationError("Invalid bag_id".into()))?;

        let max_peers = u32::from_le_bytes(
            data[32..36]
                .try_into()
                .map_err(|_| StorageError::DeserializationError("Invalid max_peers".into()))?,
        );

        Ok(Self { bag_id, max_peers })
    }
}

/// Provider list response: `storage.providerListResponse providers:(vector storage.NodeInfo) timestamp:long`
///
/// Response with a list of providers for a bag.
#[derive(Debug, Clone)]
pub struct StorageProviderListResponse {
    /// List of provider node infos.
    pub providers: Vec<StorageNodeInfo>,
    /// Timestamp when this response was created.
    pub timestamp: i64,
}

impl StorageProviderListResponse {
    /// Creates a new provider list response.
    pub fn new(providers: Vec<StorageNodeInfo>, timestamp: i64) -> Self {
        Self {
            providers,
            timestamp,
        }
    }

    /// Serializes to TL format (with schema ID).
    pub fn serialize(&self) -> Vec<u8> {
        let mut writer = TlWriter::with_capacity(100 + (self.providers.len() * 80));

        writer.write_u32(TL_STORAGE_PROVIDER_LIST_RESPONSE);

        // Write provider count as a vector length
        writer.write_u32(self.providers.len() as u32);

        // Write each provider's info data (without schema ID, just the data)
        for provider in &self.providers {
            writer.write_int256(&provider.provider_id);
            writer.write_u32(provider.address.ip);
            writer.write_u16(provider.address.port);
            writer.write_u32(provider.version);
            writer.write_u32(provider.flags);
            writer.write_u64(provider.available_space);
            writer.write_u64(provider.used_space);
            writer.write_u32(provider.bags_count);
            writer.write_u32(provider.max_chunk_size);
        }

        writer.write_i64(self.timestamp);
        writer.finish()
    }

    /// Deserializes from TL format (without schema ID).
    pub fn deserialize(data: &[u8]) -> StorageResult<Self> {
        let mut reader = TlReader::new(data);

        let provider_count = reader.read_u32()? as usize;
        let mut providers = Vec::with_capacity(provider_count);

        for _ in 0..provider_count {
            let provider_id = reader.read_int256()?;
            let ip = reader.read_u32()?;
            let port = reader.read_u16()?;
            let version = reader.read_u32()?;
            let flags = reader.read_u32()?;
            let available_space = reader.read_u64()?;
            let used_space = reader.read_u64()?;
            let bags_count = reader.read_u32()?;
            let max_chunk_size = reader.read_u32()?;

            providers.push(StorageNodeInfo {
                provider_id,
                address: StorageAddress::new(ip, port),
                version,
                flags,
                available_space,
                used_space,
                bags_count,
                max_chunk_size,
            });
        }

        let timestamp = reader.read_i64()?;

        Ok(Self {
            providers,
            timestamp,
        })
    }
}

// ============================================================================
// Query Message Structures
// ============================================================================

/// Query message: `storage.getTorrentInfo bag_id:int256`
#[derive(Debug, Clone)]
pub struct StorageGetTorrentInfo {
    /// The BagID to get info for.
    pub bag_id: BagId,
}

impl StorageGetTorrentInfo {
    /// Creates a new getTorrentInfo query.
    pub fn new(bag_id: BagId) -> Self {
        Self { bag_id }
    }

    /// Serializes the query to bytes.
    pub fn serialize(&self) -> Vec<u8> {
        let mut writer = TlWriter::with_capacity(36);
        writer.write_u32(TL_STORAGE_GET_TORRENT_INFO);
        writer.write_int256(&self.bag_id);
        writer.finish()
    }

    /// Deserializes a query from bytes (without schema prefix).
    pub fn deserialize(data: &[u8]) -> StorageResult<Self> {
        if data.len() < 32 {
            return Err(StorageError::DeserializationError(
                "getTorrentInfo data too short".into(),
            ));
        }

        let bag_id: BagId = data[0..32]
            .try_into()
            .map_err(|_| StorageError::DeserializationError("Invalid bag_id".into()))?;

        Ok(Self { bag_id })
    }
}

/// Query message: `storage.getPiece bag_id:int256 piece_id:int`
#[derive(Debug, Clone)]
pub struct StorageGetPiece {
    /// The BagID containing the piece.
    pub bag_id: BagId,
    /// The piece index.
    pub piece_id: u32,
}

impl StorageGetPiece {
    /// Creates a new getPiece query.
    pub fn new(bag_id: BagId, piece_id: u32) -> Self {
        Self { bag_id, piece_id }
    }

    /// Serializes the query to bytes.
    pub fn serialize(&self) -> Vec<u8> {
        let mut writer = TlWriter::with_capacity(40);
        writer.write_u32(TL_STORAGE_GET_PIECE);
        writer.write_int256(&self.bag_id);
        writer.write_u32(self.piece_id);
        writer.finish()
    }

    /// Deserializes a query from bytes (without schema prefix).
    pub fn deserialize(data: &[u8]) -> StorageResult<Self> {
        if data.len() < 36 {
            return Err(StorageError::DeserializationError(
                "getPiece data too short".into(),
            ));
        }

        let bag_id: BagId = data[0..32]
            .try_into()
            .map_err(|_| StorageError::DeserializationError("Invalid bag_id".into()))?;

        let piece_id = u32::from_le_bytes(
            data[32..36]
                .try_into()
                .map_err(|_| StorageError::DeserializationError("Invalid piece_id".into()))?,
        );

        Ok(Self { bag_id, piece_id })
    }
}

/// Query message: `storage.ping random_id:long`
#[derive(Debug, Clone)]
pub struct StoragePing {
    /// Random ID for the ping.
    pub random_id: i64,
}

impl StoragePing {
    /// Creates a new ping query.
    pub fn new(random_id: i64) -> Self {
        Self { random_id }
    }

    /// Serializes the query to bytes.
    pub fn serialize(&self) -> Vec<u8> {
        let mut writer = TlWriter::with_capacity(12);
        writer.write_u32(TL_STORAGE_PING);
        writer.write_i64(self.random_id);
        writer.finish()
    }

    /// Deserializes a query from bytes (without schema prefix).
    pub fn deserialize(data: &[u8]) -> StorageResult<Self> {
        if data.len() < 8 {
            return Err(StorageError::DeserializationError(
                "ping data too short".into(),
            ));
        }

        let random_id = i64::from_le_bytes(
            data[0..8]
                .try_into()
                .map_err(|_| StorageError::DeserializationError("Invalid random_id".into()))?,
        );

        Ok(Self { random_id })
    }
}

// ============================================================================
// Response Message Structures
// ============================================================================

/// Response message: `storage.pong random_id:long`
#[derive(Debug, Clone)]
pub struct StoragePong {
    /// Random ID echoed from ping.
    pub random_id: i64,
}

impl StoragePong {
    /// Creates a new pong response.
    pub fn new(random_id: i64) -> Self {
        Self { random_id }
    }

    /// Serializes the response to bytes.
    pub fn serialize(&self) -> Vec<u8> {
        let mut writer = TlWriter::with_capacity(12);
        writer.write_u32(TL_STORAGE_PONG);
        writer.write_i64(self.random_id);
        writer.finish()
    }
}

// ============================================================================
// Extensions for existing types
// ============================================================================

impl TorrentInfo {
    /// Deserializes TorrentInfo from a TL reader.
    pub fn from_tl_reader(reader: &mut TlReader) -> StorageResult<Self> {
        let chunk_size = reader.read_u32()?;
        let file_size = reader.read_u64()?;
        let root_hash = reader.read_int256()?;
        let header_size = reader.read_u64()?;
        let header_hash = reader.read_int256()?;
        let description = reader.read_string()?;

        Ok(Self {
            chunk_size,
            file_size,
            root_hash,
            header_size,
            header_hash,
            description,
        })
    }

    /// Serializes TorrentInfo to TL format.
    pub fn to_tl(&self) -> Vec<u8> {
        let mut writer = TlWriter::with_capacity(100 + self.description.len());
        writer.write_u32(TL_STORAGE_TORRENT_INFO);
        writer.write_u32(self.chunk_size);
        writer.write_u64(self.file_size);
        writer.write_int256(&self.root_hash);
        writer.write_u64(self.header_size);
        writer.write_int256(&self.header_hash);
        writer.write_string(&self.description);
        writer.finish()
    }
}

impl StoragePiece {
    /// Deserializes StoragePiece from a TL reader.
    pub fn from_tl_reader(reader: &mut TlReader) -> StorageResult<Self> {
        let proof = reader.read_bytes()?;
        let data = reader.read_bytes()?;

        Ok(Self { proof, data })
    }

    /// Serializes StoragePiece to TL format.
    pub fn to_tl(&self) -> Vec<u8> {
        let mut writer = TlWriter::with_capacity(8 + self.proof.len() + self.data.len());
        writer.write_u32(TL_STORAGE_PIECE);
        writer.write_bytes(&self.proof);
        writer.write_bytes(&self.data);
        writer.finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tl_writer_basic() {
        let mut writer = TlWriter::new();
        writer.write_u32(0x12345678);
        writer.write_i64(-1234567890);
        let data = writer.finish();

        assert_eq!(data.len(), 12);
        assert_eq!(data[0..4], [0x78, 0x56, 0x34, 0x12]);
    }

    #[test]
    fn test_tl_reader_basic() {
        let data = [0x78, 0x56, 0x34, 0x12, 0x00, 0x00, 0x00, 0x00];
        let mut reader = TlReader::new(&data);

        let value = reader.read_u32().unwrap();
        assert_eq!(value, 0x12345678);
    }

    #[test]
    fn test_tl_bytes_roundtrip() {
        let original = b"Hello, TON Storage!";

        let mut writer = TlWriter::new();
        writer.write_bytes(original);
        let data = writer.finish();

        let mut reader = TlReader::new(&data);
        let restored = reader.read_bytes().unwrap();

        assert_eq!(restored, original);
    }

    #[test]
    fn test_tl_bytes_long() {
        let original = vec![0xABu8; 300]; // > 254 bytes

        let mut writer = TlWriter::new();
        writer.write_bytes(&original);
        let data = writer.finish();

        // Should start with 254 followed by 3-byte length
        assert_eq!(data[0], 254);

        let mut reader = TlReader::new(&data);
        let restored = reader.read_bytes().unwrap();

        assert_eq!(restored, original);
    }

    #[test]
    fn test_tl_int256_roundtrip() {
        let original = [0x42u8; 32];

        let mut writer = TlWriter::new();
        writer.write_int256(&original);
        let data = writer.finish();

        let mut reader = TlReader::new(&data);
        let restored = reader.read_int256().unwrap();

        assert_eq!(restored, original);
    }

    #[test]
    fn test_storage_get_torrent_info_serialize() {
        let bag_id = [0x01u8; 32];
        let query = StorageGetTorrentInfo::new(bag_id);
        let data = query.serialize();

        assert_eq!(data.len(), 36);

        // Check schema ID
        let schema = u32::from_le_bytes(data[0..4].try_into().unwrap());
        assert_eq!(schema, TL_STORAGE_GET_TORRENT_INFO);

        // Check bag_id
        assert_eq!(&data[4..36], &bag_id);
    }

    #[test]
    fn test_storage_get_piece_serialize() {
        let bag_id = [0x02u8; 32];
        let query = StorageGetPiece::new(bag_id, 42);
        let data = query.serialize();

        assert_eq!(data.len(), 40);

        // Check schema ID
        let schema = u32::from_le_bytes(data[0..4].try_into().unwrap());
        assert_eq!(schema, TL_STORAGE_GET_PIECE);

        // Check bag_id
        assert_eq!(&data[4..36], &bag_id);

        // Check piece_id
        let piece_id = u32::from_le_bytes(data[36..40].try_into().unwrap());
        assert_eq!(piece_id, 42);
    }

    #[test]
    fn test_storage_ping_serialize() {
        let query = StoragePing::new(0x123456789ABCDEF0);
        let data = query.serialize();

        assert_eq!(data.len(), 12);

        // Check schema ID
        let schema = u32::from_le_bytes(data[0..4].try_into().unwrap());
        assert_eq!(schema, TL_STORAGE_PING);

        // Check random_id
        let random_id = i64::from_le_bytes(data[4..12].try_into().unwrap());
        assert_eq!(random_id, 0x123456789ABCDEF0);
    }

    #[test]
    fn test_storage_pong_serialize() {
        let response = StoragePong::new(0x123456789ABCDEF0);
        let data = response.serialize();

        assert_eq!(data.len(), 12);

        // Check schema ID
        let schema = u32::from_le_bytes(data[0..4].try_into().unwrap());
        assert_eq!(schema, TL_STORAGE_PONG);
    }

    #[test]
    fn test_torrent_info_tl_roundtrip() {
        let info = TorrentInfo::new(1024, [0x11u8; 32], 256, [0x22u8; 32])
            .with_description("Test torrent");

        let data = info.to_tl();

        // Skip schema ID
        let mut reader = TlReader::new(&data[4..]);
        let restored = TorrentInfo::from_tl_reader(&mut reader).unwrap();

        assert_eq!(info.chunk_size, restored.chunk_size);
        assert_eq!(info.file_size, restored.file_size);
        assert_eq!(info.root_hash, restored.root_hash);
        assert_eq!(info.header_size, restored.header_size);
        assert_eq!(info.header_hash, restored.header_hash);
        assert_eq!(info.description, restored.description);
    }

    #[test]
    fn test_storage_piece_tl_roundtrip() {
        let piece = StoragePiece::new(vec![1, 2, 3, 4], vec![5, 6, 7, 8, 9, 10]);

        let data = piece.to_tl();

        // Skip schema ID
        let mut reader = TlReader::new(&data[4..]);
        let restored = StoragePiece::from_tl_reader(&mut reader).unwrap();

        assert_eq!(piece.proof, restored.proof);
        assert_eq!(piece.data, restored.data);
    }

    #[test]
    fn test_schema_ids_are_unique() {
        let ids = [
            TL_STORAGE_GET_TORRENT_INFO,
            TL_STORAGE_GET_PIECE,
            TL_STORAGE_PING,
            TL_STORAGE_TORRENT_INFO,
            TL_STORAGE_PIECE,
            TL_STORAGE_PONG,
            TL_STORAGE_ADD_PROVIDER,
            TL_STORAGE_GET_PROVIDERS,
            TL_STORAGE_PROVIDERS,
            TL_STORAGE_UPDATE_STATE,
            TL_STORAGE_STATE,
            TL_STORAGE_ADDRESS,
            TL_STORAGE_NODE_INFO,
            TL_STORAGE_NODE_VALUE,
            TL_STORAGE_UPLOAD_SESSION_INFO,
            TL_STORAGE_CHUNK_UPLOAD_REQUEST,
            TL_STORAGE_CHUNK_UPLOAD_RESPONSE,
            TL_STORAGE_PROVIDER_LIST_REQUEST,
            TL_STORAGE_PROVIDER_LIST_RESPONSE,
        ];

        // Check all IDs are unique
        for (i, id1) in ids.iter().enumerate() {
            for (j, id2) in ids.iter().enumerate() {
                if i != j {
                    assert_ne!(id1, id2, "Schema IDs {} and {} are not unique", i, j);
                }
            }
        }
    }

    // ========================================================================
    // Upload Protocol Message Tests
    // ========================================================================

    #[test]
    fn test_serialize_storage_address() {
        let addr = StorageAddress::new(0x7f000001, 8080);
        let data = addr.to_tl_data();

        assert_eq!(data.len(), 6);
        assert_eq!(&data[0..4], &0x7f000001u32.to_le_bytes());
        assert_eq!(&data[4..6], &8080u16.to_le_bytes());
    }

    #[test]
    fn test_deserialize_storage_address() {
        let original = StorageAddress::new(0x7f000001, 8080);
        let data = original.to_tl_data();
        let restored = StorageAddress::from_tl_data(&data).unwrap();

        assert_eq!(restored.ip, original.ip);
        assert_eq!(restored.port, original.port);
    }

    #[test]
    fn test_storage_address_ipv4_conversion() {
        let ipv4 = Ipv4Addr::new(127, 0, 0, 1);
        let addr = StorageAddress::from_ipv4(ipv4, 9000);
        let converted = addr.to_ipv4();

        assert_eq!(converted, ipv4);
    }

    #[test]
    fn test_serialize_storage_node_info() {
        let provider_id = [1u8; 32];
        let addr = StorageAddress::new(0x7f000001, 8080);
        let node_info = StorageNodeInfo::new(provider_id, addr, 1, 1_000_000_000);

        let data = node_info.serialize();

        // Verify schema ID
        let schema = u32::from_le_bytes(data[0..4].try_into().unwrap());
        assert_eq!(schema, TL_STORAGE_NODE_INFO);
        // 4 (schema) + 32 (provider_id) + 4 (ip) + 2 (port) + 4 (version) + 4 (flags) + 8 (available_space) + 8 (used_space) + 4 (bags_count) + 4 (max_chunk_size) = 74
        assert!(data.len() >= 74);
    }

    #[test]
    fn test_node_info_roundtrip() {
        let provider_id = [42u8; 32];
        let addr = StorageAddress::new(0xc0a80001, 9999);
        let node_info = StorageNodeInfo {
            provider_id,
            address: addr,
            version: 2,
            flags: 0x01,
            available_space: 5_000_000_000,
            used_space: 1_000_000_000,
            bags_count: 50,
            max_chunk_size: 262144,
        };

        let data = node_info.serialize();
        // Skip schema ID (first 4 bytes) for deserialization
        let restored = StorageNodeInfo::deserialize(&data[4..]).unwrap();

        assert_eq!(node_info.provider_id, restored.provider_id);
        assert_eq!(node_info.address.ip, restored.address.ip);
        assert_eq!(node_info.address.port, restored.address.port);
        assert_eq!(node_info.version, restored.version);
        assert_eq!(node_info.flags, restored.flags);
        assert_eq!(node_info.available_space, restored.available_space);
        assert_eq!(node_info.used_space, restored.used_space);
        assert_eq!(node_info.bags_count, restored.bags_count);
        assert_eq!(node_info.max_chunk_size, restored.max_chunk_size);
    }

    #[test]
    fn test_serialize_storage_node_value_tl() {
        let provider_id = [5u8; 32];
        let addr = StorageAddress::new(0x7f000001, 8080);
        let node_info = StorageNodeInfo::new(provider_id, addr, 1, 1_000_000);
        let signature = vec![1, 2, 3, 4, 5];
        let node_value = StorageNodeValueTL::new(node_info, signature, 1234567890);

        let data = node_value.serialize();

        let schema = u32::from_le_bytes(data[0..4].try_into().unwrap());
        assert_eq!(schema, TL_STORAGE_NODE_VALUE);
    }

    #[test]
    fn test_node_value_tl_roundtrip() {
        let provider_id = [10u8; 32];
        let addr = StorageAddress::new(0xc0a80001, 8888);
        let node_info = StorageNodeInfo::new(provider_id, addr, 1, 5_000_000);
        let signature = vec![255, 254, 253];
        let timestamp = 1609459200i64;
        let node_value = StorageNodeValueTL::new(node_info, signature.clone(), timestamp);

        let data = node_value.serialize();
        let restored = StorageNodeValueTL::deserialize(&data[4..]).unwrap();

        assert_eq!(node_value.node_info.provider_id, restored.node_info.provider_id);
        assert_eq!(node_value.signature, restored.signature);
        assert_eq!(node_value.timestamp, restored.timestamp);
    }

    #[test]
    fn test_serialize_upload_session_info() {
        let session_id = [3u8; 32];
        let bag_id = [7u8; 32];
        let info = StorageUploadSessionInfo::new(session_id, bag_id, 10_000_000);

        let data = info.serialize();

        let schema = u32::from_le_bytes(data[0..4].try_into().unwrap());
        assert_eq!(schema, TL_STORAGE_UPLOAD_SESSION_INFO);
        assert_eq!(data.len(), 96); // 4 + 92 bytes of data
    }

    #[test]
    fn test_upload_session_info_roundtrip() {
        let session_id = [15u8; 32];
        let bag_id = [25u8; 32];
        let mut info = StorageUploadSessionInfo::new(session_id, bag_id, 50_000_000);
        info.uploaded_size = 25_000_000;
        info.progress = 50;
        info.peers_count = 5;
        info.state = 1;

        let data = info.serialize();
        let restored = StorageUploadSessionInfo::deserialize(&data[4..]).unwrap();

        assert_eq!(info.session_id, restored.session_id);
        assert_eq!(info.bag_id, restored.bag_id);
        assert_eq!(info.total_size, restored.total_size);
        assert_eq!(info.uploaded_size, restored.uploaded_size);
        assert_eq!(info.progress, restored.progress);
        assert_eq!(info.peers_count, restored.peers_count);
        assert_eq!(info.state, restored.state);
    }

    #[test]
    fn test_serialize_chunk_upload_request() {
        let session_id = [4u8; 32];
        let chunk_data = vec![1, 2, 3, 4, 5, 6, 7, 8];
        let req = StorageChunkUploadRequest::new(session_id, 0, chunk_data, 0x12345678);

        let data = req.serialize();

        let schema = u32::from_le_bytes(data[0..4].try_into().unwrap());
        assert_eq!(schema, TL_STORAGE_CHUNK_UPLOAD_REQUEST);
    }

    #[test]
    fn test_chunk_upload_request_roundtrip() {
        let session_id = [33u8; 32];
        let chunk_data = vec![9, 10, 11, 12, 13];
        let original = StorageChunkUploadRequest::new(session_id, 42, chunk_data.clone(), 0xABCDEF00);

        let data = original.serialize();
        let restored = StorageChunkUploadRequest::deserialize(&data[4..]).unwrap();

        assert_eq!(original.session_id, restored.session_id);
        assert_eq!(original.chunk_id, restored.chunk_id);
        assert_eq!(original.chunk_data, restored.chunk_data);
        assert_eq!(original.crc32, restored.crc32);
    }

    #[test]
    fn test_serialize_chunk_upload_response() {
        let session_id = [8u8; 32];
        let resp = StorageChunkUploadResponse::new(session_id, 1, 131072, 0);

        let data = resp.serialize();

        let schema = u32::from_le_bytes(data[0..4].try_into().unwrap());
        assert_eq!(schema, TL_STORAGE_CHUNK_UPLOAD_RESPONSE);
        // 4 (schema) + 32 (session_id) + 4 (chunk_id) + 8 (received_bytes) + 4 (status) = 52
        assert_eq!(data.len(), 52);
    }

    #[test]
    fn test_chunk_upload_response_roundtrip() {
        let session_id = [45u8; 32];
        let original = StorageChunkUploadResponse::new(session_id, 99, 262144, 0);

        let data = original.serialize();
        let restored = StorageChunkUploadResponse::deserialize(&data[4..]).unwrap();

        assert_eq!(original.session_id, restored.session_id);
        assert_eq!(original.chunk_id, restored.chunk_id);
        assert_eq!(original.received_bytes, restored.received_bytes);
        assert_eq!(original.status, restored.status);
    }

    #[test]
    fn test_serialize_provider_list_request() {
        let bag_id = [16u8; 32];
        let req = StorageProviderListRequest::new(bag_id, 10);

        let data = req.serialize();

        let schema = u32::from_le_bytes(data[0..4].try_into().unwrap());
        assert_eq!(schema, TL_STORAGE_PROVIDER_LIST_REQUEST);
        assert_eq!(data.len(), 40);
    }

    #[test]
    fn test_provider_list_request_roundtrip() {
        let bag_id = [100u8; 32];
        let original = StorageProviderListRequest::new(bag_id, 20);

        let data = original.serialize();
        let restored = StorageProviderListRequest::deserialize(&data[4..]).unwrap();

        assert_eq!(original.bag_id, restored.bag_id);
        assert_eq!(original.max_peers, restored.max_peers);
    }

    #[test]
    fn test_serialize_provider_list_response() {
        let addr1 = StorageAddress::new(0x7f000001, 8080);
        let provider1 = StorageNodeInfo::new([1u8; 32], addr1, 1, 1_000_000);

        let addr2 = StorageAddress::new(0x7f000002, 8081);
        let provider2 = StorageNodeInfo::new([2u8; 32], addr2, 1, 2_000_000);

        let resp = StorageProviderListResponse::new(vec![provider1, provider2], 1234567890);
        let data = resp.serialize();

        let schema = u32::from_le_bytes(data[0..4].try_into().unwrap());
        assert_eq!(schema, TL_STORAGE_PROVIDER_LIST_RESPONSE);
    }

    #[test]
    fn test_provider_list_response_roundtrip() {
        let mut providers = Vec::new();
        for i in 0..3 {
            let addr = StorageAddress::new(0x7f000001 + i as u32, 8080 + i as u16);
            let provider = StorageNodeInfo::new(
                [i as u8; 32],
                addr,
                1,
                1_000_000 + (i as u64 * 1000),
            );
            providers.push(provider);
        }

        let original = StorageProviderListResponse::new(providers, 1609459200);
        let data = original.serialize();
        let restored = StorageProviderListResponse::deserialize(&data[4..]).unwrap();

        assert_eq!(original.providers.len(), restored.providers.len());
        assert_eq!(original.timestamp, restored.timestamp);

        for (orig, rest) in original.providers.iter().zip(restored.providers.iter()) {
            assert_eq!(orig.provider_id, rest.provider_id);
            assert_eq!(orig.address.ip, rest.address.ip);
            assert_eq!(orig.address.port, rest.address.port);
        }
    }

    #[test]
    fn test_chunk_upload_response_status_codes() {
        let session_id = [123u8; 32];

        // Test different status codes
        let resp_success = StorageChunkUploadResponse::new(session_id, 0, 131072, 0);
        let resp_crc_error = StorageChunkUploadResponse::new(session_id, 0, 0, 1);
        let resp_full = StorageChunkUploadResponse::new(session_id, 0, 0, 2);
        let resp_error = StorageChunkUploadResponse::new(session_id, 0, 0, 3);

        assert_eq!(resp_success.status, 0);
        assert_eq!(resp_crc_error.status, 1);
        assert_eq!(resp_full.status, 2);
        assert_eq!(resp_error.status, 3);
    }

    #[test]
    fn test_upload_session_state_codes() {
        let session_id = [99u8; 32];
        let bag_id = [88u8; 32];

        // Test different state codes
        let mut info_idle = StorageUploadSessionInfo::new(session_id, bag_id, 1000);
        assert_eq!(info_idle.state, 0);

        info_idle.state = 1; // uploading
        let data = info_idle.serialize();
        let restored = StorageUploadSessionInfo::deserialize(&data[4..]).unwrap();
        assert_eq!(restored.state, 1);

        let mut info_paused = StorageUploadSessionInfo::new(session_id, bag_id, 1000);
        info_paused.state = 2; // paused
        assert_eq!(info_paused.state, 2);

        let mut info_complete = StorageUploadSessionInfo::new(session_id, bag_id, 1000);
        info_complete.state = 3; // completed
        assert_eq!(info_complete.state, 3);

        let mut info_error = StorageUploadSessionInfo::new(session_id, bag_id, 1000);
        info_error.state = 4; // error
        assert_eq!(info_error.state, 4);
    }

    #[test]
    fn test_invalid_address_data() {
        let too_short = vec![1, 2, 3];
        let result = StorageAddress::from_tl_data(&too_short);
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_node_info_data() {
        let too_short = vec![0u8; 50];
        let result = StorageNodeInfo::deserialize(&too_short);
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_session_info_data() {
        let too_short = vec![0u8; 50];
        let result = StorageUploadSessionInfo::deserialize(&too_short);
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_chunk_response_data() {
        let too_short = vec![0u8; 30];
        let result = StorageChunkUploadResponse::deserialize(&too_short);
        assert!(result.is_err());
    }

    #[test]
    fn test_provider_list_empty() {
        let original = StorageProviderListResponse::new(vec![], 1234567890);
        let data = original.serialize();
        let restored = StorageProviderListResponse::deserialize(&data[4..]).unwrap();

        assert_eq!(restored.providers.len(), 0);
        assert_eq!(restored.timestamp, 1234567890);
    }

    #[test]
    fn test_chunk_data_large() {
        let session_id = [77u8; 32];
        let large_chunk = vec![0xAAu8; 131072]; // 128 KB
        let req = StorageChunkUploadRequest::new(session_id, 0, large_chunk.clone(), 0x11223344);

        let data = req.serialize();
        let restored = StorageChunkUploadRequest::deserialize(&data[4..]).unwrap();

        assert_eq!(restored.chunk_data, large_chunk);
        assert_eq!(restored.crc32, 0x11223344);
    }

    #[test]
    fn test_tl_string_roundtrip() {
        let original = "Hello, World!";

        let mut writer = TlWriter::new();
        writer.write_string(original);
        let data = writer.finish();

        let mut reader = TlReader::new(&data);
        let restored = reader.read_string().unwrap();

        assert_eq!(restored, original);
    }

    #[test]
    fn test_tl_reader_remaining() {
        let data = [1, 2, 3, 4, 5, 6, 7, 8];
        let mut reader = TlReader::new(&data);

        assert_eq!(reader.remaining_len(), 8);

        reader.read_u32().unwrap();
        assert_eq!(reader.remaining_len(), 4);
        assert_eq!(reader.remaining(), &[5, 6, 7, 8]);
    }

    #[test]
    fn test_storage_get_torrent_info_deserialize() {
        let bag_id = [0xABu8; 32];
        let query = StorageGetTorrentInfo::new(bag_id);
        let data = query.serialize();

        // Deserialize (skip schema)
        let restored = StorageGetTorrentInfo::deserialize(&data[4..]).unwrap();
        assert_eq!(restored.bag_id, bag_id);
    }

    #[test]
    fn test_storage_get_piece_deserialize() {
        let bag_id = [0xCDu8; 32];
        let query = StorageGetPiece::new(bag_id, 123);
        let data = query.serialize();

        // Deserialize (skip schema)
        let restored = StorageGetPiece::deserialize(&data[4..]).unwrap();
        assert_eq!(restored.bag_id, bag_id);
        assert_eq!(restored.piece_id, 123);
    }

    #[test]
    fn test_storage_ping_deserialize() {
        let query = StoragePing::new(-12345);
        let data = query.serialize();

        // Deserialize (skip schema)
        let restored = StoragePing::deserialize(&data[4..]).unwrap();
        assert_eq!(restored.random_id, -12345);
    }
}
