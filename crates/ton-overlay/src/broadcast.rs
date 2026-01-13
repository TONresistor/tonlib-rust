//! Broadcast handling and propagation for overlay networks.
//!
//! This module provides types and utilities for sending and receiving broadcasts
//! in overlay networks. Broadcasts are messages sent to all nodes in an overlay.

use std::collections::HashSet;
use std::time::{SystemTime, UNIX_EPOCH};

use ton_crypto::{sha256, Ed25519Keypair, verify_signature};
use ton_rldp::FecType;

use crate::certificate::OverlayCertificate;
use crate::error::{OverlayError, Result};
use crate::tl::{
    TlReader, TlWriter, OVERLAY_BROADCAST, OVERLAY_BROADCAST_FEC, OVERLAY_BROADCAST_FEC_SHORT,
    OVERLAY_BROADCAST_TO_SIGN, PUB_ED25519,
};

/// Maximum broadcast data size (without FEC).
pub const MAX_BROADCAST_SIZE: usize = 768;

/// Maximum FEC broadcast data size.
pub const MAX_FEC_BROADCAST_SIZE: usize = 16 * 1024 * 1024; // 16 MB

/// Maximum age of a broadcast in seconds (matching official TON: 20 seconds).
pub const MAX_BROADCAST_AGE: i32 = 20;

/// Maximum future timestamp offset allowed (matching official TON: 20 seconds).
pub const MAX_BROADCAST_FUTURE: i32 = 20;

// FEC type schema IDs (from ton_rldp)
const FEC_RAPTORQ: u32 = 0x19a4f8ba;
const FEC_ROUND_ROBIN: u32 = 0x32f528d5;
const FEC_ONLINE: u32 = 0xe7c59bba;

/// Broadcast flags.
pub mod flags {
    /// Broadcast should be forwarded to all peers.
    pub const FORWARD_ALL: i32 = 0;
    /// Broadcast should not be forwarded.
    pub const NO_FORWARD: i32 = 1;
}

/// Helper function to write FecType to our TlWriter.
fn write_fec_type(writer: &mut TlWriter, fec: &FecType) {
    match fec {
        FecType::RaptorQ { data_size, symbol_size, symbols_count } => {
            writer.write_u32(FEC_RAPTORQ);
            writer.write_i32(*data_size);
            writer.write_i32(*symbol_size);
            writer.write_i32(*symbols_count);
        }
        FecType::RoundRobin { data_size, symbol_size, symbols_count } => {
            writer.write_u32(FEC_ROUND_ROBIN);
            writer.write_i32(*data_size);
            writer.write_i32(*symbol_size);
            writer.write_i32(*symbols_count);
        }
        FecType::Online { data_size, symbol_size, symbols_count } => {
            writer.write_u32(FEC_ONLINE);
            writer.write_i32(*data_size);
            writer.write_i32(*symbol_size);
            writer.write_i32(*symbols_count);
        }
    }
}

/// Helper function to read FecType from our TlReader.
fn read_fec_type(reader: &mut TlReader) -> Result<FecType> {
    let schema_id = reader.read_u32()?;
    let data_size = reader.read_i32()?;
    let symbol_size = reader.read_i32()?;
    let symbols_count = reader.read_i32()?;

    match schema_id {
        FEC_RAPTORQ => Ok(FecType::RaptorQ { data_size, symbol_size, symbols_count }),
        FEC_ROUND_ROBIN => Ok(FecType::RoundRobin { data_size, symbol_size, symbols_count }),
        FEC_ONLINE => Ok(FecType::Online { data_size, symbol_size, symbols_count }),
        _ => Err(OverlayError::TlError(format!("unknown FEC type: 0x{:08x}", schema_id))),
    }
}

/// A simple overlay broadcast message.
#[derive(Debug, Clone)]
pub struct OverlayBroadcast {
    /// Source public key.
    pub src: [u8; 32],
    /// Certificate authorizing the broadcast.
    pub certificate: OverlayCertificate,
    /// Broadcast flags.
    pub flags: i32,
    /// Broadcast data.
    pub data: Vec<u8>,
    /// Timestamp when broadcast was created.
    pub date: i32,
    /// Signature over the broadcast.
    pub signature: Vec<u8>,
}

impl OverlayBroadcast {
    /// Creates a new broadcast.
    pub fn new(data: Vec<u8>) -> Self {
        let date = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i32;

        Self {
            src: [0u8; 32],
            certificate: OverlayCertificate::empty(),
            flags: flags::FORWARD_ALL,
            data,
            date,
            signature: Vec::new(),
        }
    }

    /// Sets the certificate for the broadcast.
    pub fn with_certificate(mut self, certificate: OverlayCertificate) -> Self {
        self.certificate = certificate;
        self
    }

    /// Sets the broadcast flags.
    pub fn with_flags(mut self, flags: i32) -> Self {
        self.flags = flags;
        self
    }

    /// Computes the hash of the broadcast data.
    pub fn data_hash(&self) -> [u8; 32] {
        sha256(&self.data)
    }

    /// Computes the data to be signed.
    ///
    /// Uses `overlay.broadcast.toSign` schema as per official TON:
    /// `overlay.broadcast.toSign hash:int256 date:int = overlay.Broadcast.ToSign`
    fn compute_sign_data(&self, _overlay_id: &[u8; 32]) -> Vec<u8> {
        let mut writer = TlWriter::new();
        writer.write_u32(OVERLAY_BROADCAST_TO_SIGN);
        writer.write_int256(&sha256(&self.data)); // hash of data
        writer.write_i32(self.date);
        writer.finish()
    }

    /// Signs the broadcast with the given keypair.
    pub fn sign(&mut self, keypair: &Ed25519Keypair, overlay_id: &[u8; 32]) {
        self.src = keypair.public_key;
        let data = self.compute_sign_data(overlay_id);
        self.signature = keypair.sign(&data).to_vec();
    }

    /// Verifies the broadcast signature.
    pub fn verify_signature(&self, overlay_id: &[u8; 32]) -> Result<()> {
        if self.signature.len() != 64 {
            return Err(OverlayError::SignatureVerificationFailed(
                "invalid signature length".into(),
            ));
        }

        let data = self.compute_sign_data(overlay_id);
        let sig: [u8; 64] = self.signature.as_slice().try_into().map_err(|_| {
            OverlayError::SignatureVerificationFailed("invalid signature".into())
        })?;

        verify_signature(&self.src, &data, &sig).map_err(|e| {
            OverlayError::SignatureVerificationFailed(format!(
                "signature verification failed: {}",
                e
            ))
        })?;

        Ok(())
    }

    /// Checks if the broadcast is expired.
    pub fn is_expired(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i32;

        // Check both past and future bounds (matching official TON: ±20 seconds)
        self.date < now - MAX_BROADCAST_AGE || self.date > now + MAX_BROADCAST_FUTURE
    }

    /// Validates the broadcast completely.
    pub fn validate(&self, overlay_id: &[u8; 32]) -> Result<()> {
        // Check size
        if self.data.len() > MAX_BROADCAST_SIZE {
            return Err(OverlayError::BroadcastTooLarge {
                size: self.data.len(),
                max: MAX_BROADCAST_SIZE,
            });
        }

        // Check expiration
        if self.is_expired() {
            return Err(OverlayError::BroadcastExpired);
        }

        // Verify signature
        self.verify_signature(overlay_id)?;

        // Verify certificate allows the size
        if !self.certificate.allows_size(self.data.len()) {
            return Err(OverlayError::CertificateValidationFailed(
                "broadcast size exceeds certificate limit".into(),
            ));
        }

        Ok(())
    }

    /// Serializes the broadcast to TL format.
    pub fn to_tl(&self) -> Vec<u8> {
        let mut writer = TlWriter::new();
        self.write_to(&mut writer);
        writer.finish()
    }

    /// Writes the broadcast to a TL writer.
    pub fn write_to(&self, writer: &mut TlWriter) {
        writer.write_u32(OVERLAY_BROADCAST);
        writer.write_u32(PUB_ED25519);
        writer.write_int256(&self.src);
        self.certificate.write_to(writer);
        writer.write_i32(self.flags);
        writer.write_bytes(&self.data);
        writer.write_i32(self.date);
        writer.write_bytes(&self.signature);
    }

    /// Parses a broadcast from TL format.
    pub fn from_tl(data: &[u8]) -> Result<Self> {
        let mut reader = TlReader::new(data);
        Self::read_from(&mut reader)
    }

    /// Reads a broadcast from a TL reader.
    pub fn read_from(reader: &mut TlReader) -> Result<Self> {
        let schema = reader.read_u32()?;
        if schema != OVERLAY_BROADCAST {
            return Err(OverlayError::TlError(format!(
                "expected overlay.broadcast (0x{:08x}), got 0x{:08x}",
                OVERLAY_BROADCAST, schema
            )));
        }

        // Read source public key
        let key_type = reader.read_u32()?;
        if key_type != PUB_ED25519 {
            return Err(OverlayError::TlError(format!(
                "expected pub.ed25519 (0x{:08x}), got 0x{:08x}",
                PUB_ED25519, key_type
            )));
        }
        let src = reader.read_int256()?;

        let certificate = OverlayCertificate::read_from(reader)?;
        let flags = reader.read_i32()?;
        let data = reader.read_bytes()?;
        let date = reader.read_i32()?;
        let signature = reader.read_bytes()?;

        Ok(Self {
            src,
            certificate,
            flags,
            data,
            date,
            signature,
        })
    }
}

/// FEC broadcast for large data.
#[derive(Debug, Clone)]
pub struct OverlayBroadcastFec {
    /// Source public key.
    pub src: [u8; 32],
    /// Certificate authorizing the broadcast.
    pub certificate: OverlayCertificate,
    /// Hash of the full data.
    pub data_hash: [u8; 32],
    /// Size of the full data.
    pub data_size: i32,
    /// Broadcast flags.
    pub flags: i32,
    /// FEC-encoded data part.
    pub data: Vec<u8>,
    /// Sequence number of this FEC part.
    pub seqno: i32,
    /// FEC type configuration.
    pub fec: FecType,
    /// Timestamp when broadcast was created.
    pub date: i32,
    /// Signature over the broadcast.
    pub signature: Vec<u8>,
}

impl OverlayBroadcastFec {
    /// Creates a new FEC broadcast.
    pub fn new(
        data_hash: [u8; 32],
        data_size: i32,
        fec: FecType,
        part_data: Vec<u8>,
        seqno: i32,
    ) -> Self {
        let date = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i32;

        Self {
            src: [0u8; 32],
            certificate: OverlayCertificate::empty(),
            data_hash,
            data_size,
            flags: flags::FORWARD_ALL,
            data: part_data,
            seqno,
            fec,
            date,
            signature: Vec::new(),
        }
    }

    /// Sets the certificate for the broadcast.
    pub fn with_certificate(mut self, certificate: OverlayCertificate) -> Self {
        self.certificate = certificate;
        self
    }

    /// Computes the data to be signed.
    fn compute_sign_data(&self, overlay_id: &[u8; 32]) -> Vec<u8> {
        let mut writer = TlWriter::new();
        writer.write_u32(OVERLAY_BROADCAST_FEC);
        writer.write_int256(overlay_id);
        writer.write_int256(&self.data_hash);
        writer.write_i32(self.data_size);
        writer.write_i32(self.flags);
        writer.write_int256(&sha256(&self.data));
        writer.write_i32(self.seqno);
        // Write FEC type
        write_fec_type(&mut writer, &self.fec);
        writer.write_i32(self.date);
        writer.finish()
    }

    /// Signs the broadcast with the given keypair.
    pub fn sign(&mut self, keypair: &Ed25519Keypair, overlay_id: &[u8; 32]) {
        self.src = keypair.public_key;
        let data = self.compute_sign_data(overlay_id);
        self.signature = keypair.sign(&data).to_vec();
    }

    /// Verifies the broadcast signature.
    pub fn verify_signature(&self, overlay_id: &[u8; 32]) -> Result<()> {
        if self.signature.len() != 64 {
            return Err(OverlayError::SignatureVerificationFailed(
                "invalid signature length".into(),
            ));
        }

        let data = self.compute_sign_data(overlay_id);
        let sig: [u8; 64] = self.signature.as_slice().try_into().map_err(|_| {
            OverlayError::SignatureVerificationFailed("invalid signature".into())
        })?;

        verify_signature(&self.src, &data, &sig).map_err(|e| {
            OverlayError::SignatureVerificationFailed(format!(
                "signature verification failed: {}",
                e
            ))
        })?;

        Ok(())
    }

    /// Checks if the broadcast is expired.
    pub fn is_expired(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i32;

        // Check both past and future bounds (matching official TON: ±20 seconds)
        self.date < now - MAX_BROADCAST_AGE || self.date > now + MAX_BROADCAST_FUTURE
    }

    /// Serializes the broadcast to TL format.
    pub fn to_tl(&self) -> Vec<u8> {
        let mut writer = TlWriter::new();
        self.write_to(&mut writer);
        writer.finish()
    }

    /// Writes the broadcast to a TL writer.
    pub fn write_to(&self, writer: &mut TlWriter) {
        writer.write_u32(OVERLAY_BROADCAST_FEC);
        writer.write_u32(PUB_ED25519);
        writer.write_int256(&self.src);
        self.certificate.write_to(writer);
        writer.write_int256(&self.data_hash);
        writer.write_i32(self.data_size);
        writer.write_i32(self.flags);
        writer.write_bytes(&self.data);
        writer.write_i32(self.seqno);
        write_fec_type(writer, &self.fec);
        writer.write_i32(self.date);
        writer.write_bytes(&self.signature);
    }

    /// Parses a broadcast from TL format.
    pub fn from_tl(data: &[u8]) -> Result<Self> {
        let mut reader = TlReader::new(data);
        Self::read_from(&mut reader)
    }

    /// Reads a broadcast from a TL reader.
    pub fn read_from(reader: &mut TlReader) -> Result<Self> {
        let schema = reader.read_u32()?;
        if schema != OVERLAY_BROADCAST_FEC {
            return Err(OverlayError::TlError(format!(
                "expected overlay.broadcastFec (0x{:08x}), got 0x{:08x}",
                OVERLAY_BROADCAST_FEC, schema
            )));
        }

        // Read source public key
        let key_type = reader.read_u32()?;
        if key_type != PUB_ED25519 {
            return Err(OverlayError::TlError(format!(
                "expected pub.ed25519 (0x{:08x}), got 0x{:08x}",
                PUB_ED25519, key_type
            )));
        }
        let src = reader.read_int256()?;

        let certificate = OverlayCertificate::read_from(reader)?;
        let data_hash = reader.read_int256()?;
        let data_size = reader.read_i32()?;
        let flags = reader.read_i32()?;
        let data = reader.read_bytes()?;
        let seqno = reader.read_i32()?;
        let fec = read_fec_type(reader)?;
        let date = reader.read_i32()?;
        let signature = reader.read_bytes()?;

        Ok(Self {
            src,
            certificate,
            data_hash,
            data_size,
            flags,
            data,
            seqno,
            fec,
            date,
            signature,
        })
    }
}

/// Short FEC broadcast (for subsequent parts).
#[derive(Debug, Clone)]
pub struct OverlayBroadcastFecShort {
    /// Source public key.
    pub src: [u8; 32],
    /// Certificate authorizing the broadcast.
    pub certificate: OverlayCertificate,
    /// Hash of the full broadcast.
    pub broadcast_hash: [u8; 32],
    /// Hash of this part's data.
    pub part_data_hash: [u8; 32],
    /// Sequence number of this part.
    pub seqno: i32,
    /// Signature over the broadcast.
    pub signature: Vec<u8>,
}

impl OverlayBroadcastFecShort {
    /// Creates a new short FEC broadcast.
    pub fn new(broadcast_hash: [u8; 32], part_data_hash: [u8; 32], seqno: i32) -> Self {
        Self {
            src: [0u8; 32],
            certificate: OverlayCertificate::empty(),
            broadcast_hash,
            part_data_hash,
            seqno,
            signature: Vec::new(),
        }
    }

    /// Serializes the broadcast to TL format.
    pub fn to_tl(&self) -> Vec<u8> {
        let mut writer = TlWriter::new();
        self.write_to(&mut writer);
        writer.finish()
    }

    /// Writes the broadcast to a TL writer.
    pub fn write_to(&self, writer: &mut TlWriter) {
        writer.write_u32(OVERLAY_BROADCAST_FEC_SHORT);
        writer.write_u32(PUB_ED25519);
        writer.write_int256(&self.src);
        self.certificate.write_to(writer);
        writer.write_int256(&self.broadcast_hash);
        writer.write_int256(&self.part_data_hash);
        writer.write_i32(self.seqno);
        writer.write_bytes(&self.signature);
    }
}

/// Tracks seen broadcasts to avoid duplicates.
#[derive(Debug, Default)]
pub struct BroadcastCache {
    /// Hashes of seen broadcasts.
    seen: HashSet<[u8; 32]>,
    /// Maximum number of entries to keep.
    max_entries: usize,
}

impl BroadcastCache {
    /// Creates a new broadcast cache.
    pub fn new(max_entries: usize) -> Self {
        Self {
            seen: HashSet::new(),
            max_entries,
        }
    }

    /// Checks if a broadcast has been seen.
    pub fn has_seen(&self, hash: &[u8; 32]) -> bool {
        self.seen.contains(hash)
    }

    /// Marks a broadcast as seen.
    ///
    /// Returns true if the broadcast was not previously seen.
    pub fn mark_seen(&mut self, hash: [u8; 32]) -> bool {
        if self.seen.contains(&hash) {
            return false;
        }

        // Simple cleanup: if at capacity, remove half the entries
        // In production, you'd want a proper LRU cache
        if self.seen.len() >= self.max_entries {
            let to_remove: Vec<_> = self.seen.iter().take(self.max_entries / 2).copied().collect();
            for h in to_remove {
                self.seen.remove(&h);
            }
        }

        self.seen.insert(hash);
        true
    }

    /// Clears all entries.
    pub fn clear(&mut self) {
        self.seen.clear();
    }

    /// Returns the number of entries.
    pub fn len(&self) -> usize {
        self.seen.len()
    }

    /// Returns true if the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }
}

/// Any type of overlay broadcast.
#[derive(Debug, Clone)]
pub enum Broadcast {
    /// Simple broadcast.
    Simple(OverlayBroadcast),
    /// FEC broadcast.
    Fec(OverlayBroadcastFec),
    /// Short FEC broadcast.
    FecShort(OverlayBroadcastFecShort),
}

impl Broadcast {
    /// Returns the source public key.
    pub fn src(&self) -> &[u8; 32] {
        match self {
            Broadcast::Simple(b) => &b.src,
            Broadcast::Fec(b) => &b.src,
            Broadcast::FecShort(b) => &b.src,
        }
    }

    /// Returns the hash of the broadcast data.
    pub fn data_hash(&self) -> [u8; 32] {
        match self {
            Broadcast::Simple(b) => b.data_hash(),
            Broadcast::Fec(b) => b.data_hash,
            Broadcast::FecShort(b) => b.broadcast_hash,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_overlay_broadcast_creation() {
        let broadcast = OverlayBroadcast::new(b"test data".to_vec());
        assert_eq!(broadcast.data, b"test data");
        assert!(broadcast.signature.is_empty());
    }

    #[test]
    fn test_overlay_broadcast_sign_verify() {
        let keypair = Ed25519Keypair::generate();
        let overlay_id = [1u8; 32];

        let mut broadcast = OverlayBroadcast::new(b"test data".to_vec());
        broadcast.sign(&keypair, &overlay_id);

        assert!(!broadcast.signature.is_empty());
        assert!(broadcast.verify_signature(&overlay_id).is_ok());
    }

    #[test]
    fn test_overlay_broadcast_roundtrip() {
        let keypair = Ed25519Keypair::generate();
        let overlay_id = [1u8; 32];

        let mut broadcast = OverlayBroadcast::new(b"test data".to_vec());
        broadcast.sign(&keypair, &overlay_id);

        let tl_data = broadcast.to_tl();
        let parsed = OverlayBroadcast::from_tl(&tl_data).unwrap();

        assert_eq!(parsed.src, broadcast.src);
        assert_eq!(parsed.data, broadcast.data);
        assert_eq!(parsed.date, broadcast.date);
        assert_eq!(parsed.signature, broadcast.signature);

        assert!(parsed.verify_signature(&overlay_id).is_ok());
    }

    #[test]
    fn test_overlay_broadcast_validation() {
        let keypair = Ed25519Keypair::generate();
        let overlay_id = [1u8; 32];

        let mut broadcast = OverlayBroadcast::new(b"test".to_vec());
        broadcast.sign(&keypair, &overlay_id);

        // Should pass validation
        assert!(broadcast.validate(&overlay_id).is_ok());
    }

    #[test]
    fn test_overlay_broadcast_too_large() {
        let keypair = Ed25519Keypair::generate();
        let overlay_id = [1u8; 32];

        let large_data = vec![0u8; MAX_BROADCAST_SIZE + 1];
        let mut broadcast = OverlayBroadcast::new(large_data);
        broadcast.sign(&keypair, &overlay_id);

        // Should fail validation due to size
        let result = broadcast.validate(&overlay_id);
        assert!(matches!(result, Err(OverlayError::BroadcastTooLarge { .. })));
    }

    #[test]
    fn test_overlay_broadcast_invalid_signature() {
        let keypair = Ed25519Keypair::generate();
        let overlay_id = [1u8; 32];

        let mut broadcast = OverlayBroadcast::new(b"test".to_vec());
        broadcast.sign(&keypair, &overlay_id);

        // Corrupt the signature - should fail verification
        if !broadcast.signature.is_empty() {
            broadcast.signature[0] ^= 0xFF;
        }
        assert!(broadcast.verify_signature(&overlay_id).is_err());
    }

    #[test]
    fn test_overlay_broadcast_tampered_data() {
        let keypair = Ed25519Keypair::generate();
        let overlay_id = [1u8; 32];

        let mut broadcast = OverlayBroadcast::new(b"test".to_vec());
        broadcast.sign(&keypair, &overlay_id);

        // Tamper with the data - should fail verification since data hash changes
        broadcast.data = b"tampered".to_vec();
        assert!(broadcast.verify_signature(&overlay_id).is_err());
    }

    #[test]
    fn test_broadcast_cache() {
        let mut cache = BroadcastCache::new(100);

        let hash1 = [1u8; 32];
        let hash2 = [2u8; 32];

        // First time should return true
        assert!(cache.mark_seen(hash1));
        assert!(!cache.mark_seen(hash1)); // Second time should return false

        assert!(cache.has_seen(&hash1));
        assert!(!cache.has_seen(&hash2));

        assert!(cache.mark_seen(hash2));
        assert_eq!(cache.len(), 2);
    }

    #[test]
    fn test_broadcast_cache_cleanup() {
        let mut cache = BroadcastCache::new(10);

        // Fill the cache
        for i in 0..20u8 {
            let hash = [i; 32];
            cache.mark_seen(hash);
        }

        // Should have cleaned up some entries
        assert!(cache.len() <= 15);
    }

    #[test]
    fn test_fec_broadcast_creation() {
        let data_hash = [1u8; 32];
        let fec = FecType::raptorq(1024, 768, 2);
        let part_data = vec![0u8; 768];

        let broadcast = OverlayBroadcastFec::new(data_hash, 1024, fec, part_data.clone(), 0);

        assert_eq!(broadcast.data_hash, data_hash);
        assert_eq!(broadcast.data_size, 1024);
        assert_eq!(broadcast.seqno, 0);
        assert_eq!(broadcast.data, part_data);
    }

    #[test]
    fn test_fec_broadcast_sign_verify() {
        let keypair = Ed25519Keypair::generate();
        let overlay_id = [1u8; 32];

        let data_hash = [1u8; 32];
        let fec = FecType::raptorq(1024, 768, 2);
        let part_data = vec![0u8; 768];

        let mut broadcast = OverlayBroadcastFec::new(data_hash, 1024, fec, part_data, 0);
        broadcast.sign(&keypair, &overlay_id);

        assert!(!broadcast.signature.is_empty());
        assert!(broadcast.verify_signature(&overlay_id).is_ok());
    }

    #[test]
    fn test_fec_broadcast_roundtrip() {
        let keypair = Ed25519Keypair::generate();
        let overlay_id = [1u8; 32];

        let data_hash = [1u8; 32];
        let fec = FecType::raptorq(1024, 768, 2);
        let part_data = vec![0u8; 768];

        let mut broadcast = OverlayBroadcastFec::new(data_hash, 1024, fec, part_data, 0);
        broadcast.sign(&keypair, &overlay_id);

        let tl_data = broadcast.to_tl();
        let parsed = OverlayBroadcastFec::from_tl(&tl_data).unwrap();

        assert_eq!(parsed.src, broadcast.src);
        assert_eq!(parsed.data_hash, broadcast.data_hash);
        assert_eq!(parsed.data_size, broadcast.data_size);
        assert_eq!(parsed.seqno, broadcast.seqno);
        assert_eq!(parsed.fec, broadcast.fec);
        assert!(parsed.verify_signature(&overlay_id).is_ok());
    }
}
