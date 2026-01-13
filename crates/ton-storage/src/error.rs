//! Error types for TON Storage operations.
//!
//! This module defines comprehensive error types for all storage operations including
//! download, upload, provider management, and DHT signing operations.

use thiserror::Error;

/// Errors that can occur during TON Storage operations.
#[derive(Debug, Error)]
pub enum StorageError {
    /// Invalid chunk size specified.
    #[error("Invalid chunk size: {0} (must be > 0)")]
    InvalidChunkSize(usize),

    /// Chunk index out of bounds.
    #[error("Chunk index {index} out of bounds (total chunks: {total})")]
    ChunkIndexOutOfBounds {
        /// The requested chunk index.
        index: usize,
        /// Total number of chunks.
        total: usize,
    },

    /// Invalid Merkle proof.
    #[error("Invalid Merkle proof: {0}")]
    InvalidMerkleProof(String),

    /// Hash mismatch during verification.
    #[error("Hash mismatch: expected {expected}, got {actual}")]
    HashMismatch {
        /// Expected hash (hex encoded).
        expected: String,
        /// Actual hash (hex encoded).
        actual: String,
    },

    /// Invalid torrent info structure.
    #[error("Invalid torrent info: {0}")]
    InvalidTorrentInfo(String),

    /// Invalid torrent header structure.
    #[error("Invalid torrent header: {0}")]
    InvalidTorrentHeader(String),

    /// Invalid BagID format.
    #[error("Invalid BagID: {0}")]
    InvalidBagId(String),

    /// File entry not found in bag.
    #[error("File not found in bag: {0}")]
    FileNotFound(String),

    /// Empty data provided where non-empty data was expected.
    #[error("Empty data not allowed")]
    EmptyData,

    /// Serialization error.
    #[error("Serialization error: {0}")]
    SerializationError(String),

    /// Deserialization error.
    #[error("Deserialization error: {0}")]
    DeserializationError(String),

    /// Cell operation error.
    #[error("Cell error: {0}")]
    CellError(String),

    // ===== UPLOAD ERRORS =====
    /// Errors related to uploading bags.
    #[error("Upload error: {0}")]
    UploadError(#[from] UploadError),

    // ===== PROVIDER ERRORS =====
    /// Errors related to storage provider operations.
    #[error("Provider error: {0}")]
    ProviderError(#[from] ProviderError),

    // ===== DHT SIGNING ERRORS =====
    /// Errors related to DHT signing operations.
    #[error("DHT signing error: {0}")]
    DhtSigningError(#[from] DhtSigningError),

    /// I/O error during storage operations.
    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),

    /// Network operation failed.
    #[error("Network error: {0}")]
    NetworkError(String),

    /// Invalid state transition in session.
    #[error("Invalid state transition: {0}")]
    InvalidStateTransition(String),
}

/// Errors that can occur during upload operations.
#[derive(Debug, Error)]
pub enum UploadError {
    /// Invalid bag format.
    #[error("Invalid bag: {0}")]
    InvalidBag(String),

    /// Invalid file in the bag.
    #[error("Invalid file: {0}")]
    InvalidFile(String),

    /// Upload to peer failed.
    #[error("Upload failed to peer {peer_addr}: {reason}")]
    UploadFailed {
        /// The peer address that failed.
        peer_addr: String,
        /// Reason for the failure.
        reason: String,
    },

    /// DHT announcement failed.
    #[error("DHT announcement failed: {reason}")]
    DhtAnnouncementFailed {
        /// Reason for the failure.
        reason: String,
    },
}

/// Errors that can occur during provider operations.
#[derive(Debug, Error)]
pub enum ProviderError {
    /// Storage backend error.
    #[error("Storage backend error: {0}")]
    StorageBackendError(String),

    /// Request handling failed.
    #[error("Request handling failed: {0}")]
    RequestHandlingFailed(String),

    /// Bandwidth limit exceeded.
    #[error("Bandwidth limit exceeded")]
    BandwidthLimitExceeded,

    /// Bag not found in storage.
    #[error("Bag not found: {bag_id}")]
    BagNotFound {
        /// The bag ID that was not found.
        bag_id: String,
    },

    /// Storage capacity exceeded.
    #[error("Storage capacity exceeded: max {max_bytes} bytes")]
    CapacityExceeded {
        /// Maximum storage capacity in bytes.
        max_bytes: u64,
    },
}

/// Errors that can occur during DHT signing operations.
#[derive(Debug, Error)]
pub enum DhtSigningError {
    /// Signing operation failed.
    #[error("Signing failed: {0}")]
    SigningFailed(String),

    /// Invalid key pair for signing.
    #[error("Invalid key pair for signing")]
    InvalidKeyPair,
}

/// Result type for TON Storage operations.
///
/// This is the standard return type for all storage operations. It simplifies
/// error handling by providing a single, comprehensive error type that covers
/// all possible failure modes.
pub type StorageResult<T> = Result<T, StorageError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = StorageError::InvalidChunkSize(0);
        assert_eq!(format!("{}", err), "Invalid chunk size: 0 (must be > 0)");

        let err = StorageError::ChunkIndexOutOfBounds { index: 5, total: 3 };
        assert_eq!(
            format!("{}", err),
            "Chunk index 5 out of bounds (total chunks: 3)"
        );

        let err = StorageError::HashMismatch {
            expected: "abc".to_string(),
            actual: "def".to_string(),
        };
        assert_eq!(format!("{}", err), "Hash mismatch: expected abc, got def");
    }

    #[test]
    fn test_error_debug() {
        let err = StorageError::EmptyData;
        let debug_str = format!("{:?}", err);
        assert!(debug_str.contains("EmptyData"));
    }

    #[test]
    fn test_upload_error_invalid_bag() {
        let err = UploadError::InvalidBag("corrupted data".to_string());
        assert_eq!(format!("{}", err), "Invalid bag: corrupted data");
    }

    #[test]
    fn test_upload_error_invalid_file() {
        let err = UploadError::InvalidFile("missing file".to_string());
        assert_eq!(format!("{}", err), "Invalid file: missing file");
    }

    #[test]
    fn test_upload_error_upload_failed() {
        let err = UploadError::UploadFailed {
            peer_addr: "127.0.0.1:8080".to_string(),
            reason: "connection timeout".to_string(),
        };
        assert_eq!(
            format!("{}", err),
            "Upload failed to peer 127.0.0.1:8080: connection timeout"
        );
    }

    #[test]
    fn test_upload_error_dht_announcement() {
        let err = UploadError::DhtAnnouncementFailed {
            reason: "DHT unreachable".to_string(),
        };
        assert_eq!(
            format!("{}", err),
            "DHT announcement failed: DHT unreachable"
        );
    }

    #[test]
    fn test_provider_error_storage_backend() {
        let err = ProviderError::StorageBackendError("disk full".to_string());
        assert_eq!(format!("{}", err), "Storage backend error: disk full");
    }

    #[test]
    fn test_provider_error_request_handling() {
        let err = ProviderError::RequestHandlingFailed("malformed request".to_string());
        assert_eq!(format!("{}", err), "Request handling failed: malformed request");
    }

    #[test]
    fn test_provider_error_bandwidth_limit() {
        let err = ProviderError::BandwidthLimitExceeded;
        assert_eq!(format!("{}", err), "Bandwidth limit exceeded");
    }

    #[test]
    fn test_provider_error_bag_not_found() {
        let err = ProviderError::BagNotFound {
            bag_id: "abc123".to_string(),
        };
        assert_eq!(format!("{}", err), "Bag not found: abc123");
    }

    #[test]
    fn test_provider_error_capacity_exceeded() {
        let err = ProviderError::CapacityExceeded {
            max_bytes: 1024 * 1024,
        };
        assert_eq!(
            format!("{}", err),
            "Storage capacity exceeded: max 1048576 bytes"
        );
    }

    #[test]
    fn test_dht_signing_error_signing_failed() {
        let err = DhtSigningError::SigningFailed("invalid key".to_string());
        assert_eq!(format!("{}", err), "Signing failed: invalid key");
    }

    #[test]
    fn test_dht_signing_error_invalid_keypair() {
        let err = DhtSigningError::InvalidKeyPair;
        assert_eq!(format!("{}", err), "Invalid key pair for signing");
    }

    #[test]
    fn test_storage_error_from_upload_error() {
        let upload_err = UploadError::InvalidBag("test".to_string());
        let storage_err: StorageError = upload_err.into();
        assert!(format!("{}", storage_err).contains("Invalid bag"));
    }

    #[test]
    fn test_storage_error_from_provider_error() {
        let provider_err = ProviderError::StorageBackendError("test".to_string());
        let storage_err: StorageError = provider_err.into();
        assert!(format!("{}", storage_err).contains("Storage backend error"));
    }

    #[test]
    fn test_storage_error_from_dht_signing_error() {
        let signing_err = DhtSigningError::InvalidKeyPair;
        let storage_err: StorageError = signing_err.into();
        assert!(format!("{}", storage_err).contains("Invalid key pair"));
    }
}
