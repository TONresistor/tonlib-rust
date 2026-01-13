//! Certificate validation for overlay broadcasts.
//!
//! Certificates authorize nodes to send broadcasts in an overlay.
//! They are issued by authorized parties and have expiration times.

use std::time::{SystemTime, UNIX_EPOCH};

use ton_crypto::{sha256, Ed25519Keypair, verify_signature};

use crate::error::{OverlayError, Result};
use crate::tl::{
    TlReader, TlWriter, OVERLAY_CERTIFICATE, OVERLAY_CERTIFICATE_ID, OVERLAY_EMPTY_CERTIFICATE,
    PUB_ED25519,
};

/// Calculate the ADNL short ID from an Ed25519 public key.
///
/// The ADNL short ID is calculated as:
/// SHA256(pub.ed25519#4813b4c6 key:int256)
///
/// This is the standard way to derive an ADNL address from a public key.
pub fn calculate_adnl_short_id(public_key: &[u8; 32]) -> [u8; 32] {
    let mut writer = TlWriter::new();
    writer.write_u32(PUB_ED25519);
    writer.write_int256(public_key);
    sha256(&writer.finish())
}

/// Maximum certificate size in bytes.
pub const MAX_CERTIFICATE_SIZE: usize = 1024;

/// Certificate for authorizing overlay broadcasts.
#[derive(Debug, Clone)]
#[derive(Default)]
pub enum OverlayCertificate {
    /// Empty certificate (no authorization required).
    #[default]
    Empty,
    /// Full certificate with authorization.
    Full {
        /// Public key of the certificate issuer.
        issued_by: [u8; 32],
        /// Expiration timestamp (Unix time).
        expire_at: i32,
        /// Maximum broadcast size allowed.
        max_size: i32,
        /// Signature over the certificate data.
        signature: Vec<u8>,
    },
}

impl OverlayCertificate {
    /// Creates a new empty certificate.
    pub fn empty() -> Self {
        Self::Empty
    }

    /// Creates a new certificate.
    pub fn new(issued_by: [u8; 32], expire_at: i32, max_size: i32) -> Self {
        Self::Full {
            issued_by,
            expire_at,
            max_size,
            signature: Vec::new(),
        }
    }

    /// Returns true if this is an empty certificate.
    pub fn is_empty(&self) -> bool {
        matches!(self, Self::Empty)
    }

    /// Returns the issuer's public key (if not empty).
    pub fn issued_by(&self) -> Option<&[u8; 32]> {
        match self {
            Self::Empty => None,
            Self::Full { issued_by, .. } => Some(issued_by),
        }
    }

    /// Returns the expiration time (if not empty).
    pub fn expire_at(&self) -> Option<i32> {
        match self {
            Self::Empty => None,
            Self::Full { expire_at, .. } => Some(*expire_at),
        }
    }

    /// Returns the maximum size (if not empty).
    pub fn max_size(&self) -> Option<i32> {
        match self {
            Self::Empty => None,
            Self::Full { max_size, .. } => Some(*max_size),
        }
    }

    /// Computes the certificate ID for signing.
    ///
    /// Certificate ID is computed as:
    /// SHA256(overlay.certificateId overlay_id:int256 node:int256 expire_at:int max_size:int)
    ///
    /// **Important**: The `node_adnl_id` parameter must be the ADNL short ID of the node,
    /// calculated as SHA256(pub.ed25519#4813b4c6 key:int256). Use `calculate_adnl_short_id()`
    /// to compute this from a public key.
    fn compute_certificate_id(
        overlay_id: &[u8; 32],
        node_adnl_id: &[u8; 32],
        expire_at: i32,
        max_size: i32,
    ) -> [u8; 32] {
        let mut writer = TlWriter::new();
        writer.write_u32(OVERLAY_CERTIFICATE_ID);
        writer.write_int256(overlay_id);
        writer.write_int256(node_adnl_id);
        writer.write_i32(expire_at);
        writer.write_i32(max_size);
        sha256(&writer.finish())
    }

    /// Signs the certificate with the issuer's keypair.
    ///
    /// **Important**: The `node_adnl_id` parameter must be the ADNL short ID of the node,
    /// not the raw public key. Use `calculate_adnl_short_id()` to compute this from a public key.
    pub fn sign(
        &mut self,
        keypair: &Ed25519Keypair,
        overlay_id: &[u8; 32],
        node_adnl_id: &[u8; 32],
    ) {
        if let Self::Full {
            expire_at,
            max_size,
            signature,
            ..
        } = self
        {
            let cert_id = Self::compute_certificate_id(overlay_id, node_adnl_id, *expire_at, *max_size);
            *signature = keypair.sign(&cert_id).to_vec();
        }
    }

    /// Signs the certificate for a node identified by its public key.
    ///
    /// This is a convenience method that calculates the ADNL short ID from the node's
    /// public key before signing.
    pub fn sign_for_node(
        &mut self,
        keypair: &Ed25519Keypair,
        overlay_id: &[u8; 32],
        node_public_key: &[u8; 32],
    ) {
        let node_adnl_id = calculate_adnl_short_id(node_public_key);
        self.sign(keypair, overlay_id, &node_adnl_id);
    }

    /// Verifies the certificate signature.
    ///
    /// **Important**: The `node_adnl_id` parameter must be the ADNL short ID of the node,
    /// not the raw public key. Use `calculate_adnl_short_id()` to compute this from a public key.
    pub fn verify(&self, overlay_id: &[u8; 32], node_adnl_id: &[u8; 32]) -> Result<()> {
        match self {
            Self::Empty => Ok(()), // Empty certificates are always valid
            Self::Full {
                issued_by,
                expire_at,
                max_size,
                signature,
            } => {
                // Compute certificate ID using ADNL short ID
                let cert_id =
                    Self::compute_certificate_id(overlay_id, node_adnl_id, *expire_at, *max_size);

                // Verify signature
                if signature.len() != 64 {
                    return Err(OverlayError::CertificateValidationFailed(
                        "invalid signature length".into(),
                    ));
                }

                let sig: [u8; 64] = signature.as_slice().try_into().map_err(|_| {
                    OverlayError::CertificateValidationFailed("invalid signature".into())
                })?;

                verify_signature(issued_by, &cert_id, &sig).map_err(|e| {
                    OverlayError::CertificateValidationFailed(format!(
                        "signature verification failed: {}",
                        e
                    ))
                })?;

                Ok(())
            }
        }
    }

    /// Verifies the certificate signature for a node identified by its public key.
    ///
    /// This is a convenience method that calculates the ADNL short ID from the node's
    /// public key before verifying.
    pub fn verify_for_node(&self, overlay_id: &[u8; 32], node_public_key: &[u8; 32]) -> Result<()> {
        let node_adnl_id = calculate_adnl_short_id(node_public_key);
        self.verify(overlay_id, &node_adnl_id)
    }

    /// Checks if the certificate is expired.
    pub fn is_expired(&self) -> bool {
        match self {
            Self::Empty => false,
            Self::Full { expire_at, .. } => {
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs() as i32;
                *expire_at <= now
            }
        }
    }

    /// Checks if a broadcast of the given size is allowed by this certificate.
    pub fn allows_size(&self, size: usize) -> bool {
        match self {
            Self::Empty => true, // Empty certificate allows any size
            Self::Full { max_size, .. } => size <= *max_size as usize,
        }
    }

    /// Validates the certificate completely.
    ///
    /// **Important**: The `node_adnl_id` parameter must be the ADNL short ID of the node,
    /// not the raw public key. Use `calculate_adnl_short_id()` to compute this from a public key.
    pub fn validate(&self, overlay_id: &[u8; 32], node_adnl_id: &[u8; 32]) -> Result<()> {
        // Check expiration
        if self.is_expired() {
            return Err(OverlayError::CertificateExpired);
        }

        // Verify signature
        self.verify(overlay_id, node_adnl_id)?;

        Ok(())
    }

    /// Validates the certificate for a node identified by its public key.
    ///
    /// This is a convenience method that calculates the ADNL short ID from the node's
    /// public key before validating.
    pub fn validate_for_node(&self, overlay_id: &[u8; 32], node_public_key: &[u8; 32]) -> Result<()> {
        let node_adnl_id = calculate_adnl_short_id(node_public_key);
        self.validate(overlay_id, &node_adnl_id)
    }

    /// Serializes the certificate to TL format.
    pub fn to_tl(&self) -> Vec<u8> {
        let mut writer = TlWriter::new();
        self.write_to(&mut writer);
        writer.finish()
    }

    /// Writes the certificate to a TL writer.
    pub fn write_to(&self, writer: &mut TlWriter) {
        match self {
            Self::Empty => {
                writer.write_u32(OVERLAY_EMPTY_CERTIFICATE);
            }
            Self::Full {
                issued_by,
                expire_at,
                max_size,
                signature,
            } => {
                writer.write_u32(OVERLAY_CERTIFICATE);
                writer.write_u32(PUB_ED25519);
                writer.write_int256(issued_by);
                writer.write_i32(*expire_at);
                writer.write_i32(*max_size);
                writer.write_bytes(signature);
            }
        }
    }

    /// Parses a certificate from TL format.
    pub fn from_tl(data: &[u8]) -> Result<Self> {
        let mut reader = TlReader::new(data);
        Self::read_from(&mut reader)
    }

    /// Reads a certificate from a TL reader.
    pub fn read_from(reader: &mut TlReader) -> Result<Self> {
        let schema = reader.read_u32()?;

        match schema {
            OVERLAY_EMPTY_CERTIFICATE => Ok(Self::Empty),
            OVERLAY_CERTIFICATE => {
                // Read public key
                let key_type = reader.read_u32()?;
                if key_type != PUB_ED25519 {
                    return Err(OverlayError::TlError(format!(
                        "expected pub.ed25519 (0x{:08x}), got 0x{:08x}",
                        PUB_ED25519, key_type
                    )));
                }
                let issued_by = reader.read_int256()?;
                let expire_at = reader.read_i32()?;
                let max_size = reader.read_i32()?;
                let signature = reader.read_bytes()?;

                Ok(Self::Full {
                    issued_by,
                    expire_at,
                    max_size,
                    signature,
                })
            }
            _ => Err(OverlayError::TlError(format!(
                "expected certificate schema, got 0x{:08x}",
                schema
            ))),
        }
    }
}


/// Builder for creating and signing certificates.
///
/// The certificate binds a specific node (identified by ADNL short ID) to an overlay,
/// granting them permission to broadcast.
pub struct CertificateBuilder {
    overlay_id: [u8; 32],
    node_adnl_id: [u8; 32],
    expire_at: i32,
    max_size: i32,
}

impl CertificateBuilder {
    /// Creates a new certificate builder with the node's ADNL short ID.
    ///
    /// **Important**: The `node_adnl_id` must be the ADNL short ID, calculated as
    /// SHA256(pub.ed25519#4813b4c6 key:int256). Use `calculate_adnl_short_id()` to compute this.
    pub fn new(overlay_id: [u8; 32], node_adnl_id: [u8; 32]) -> Self {
        // Default: expire in 24 hours, max 1MB
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i32;

        Self {
            overlay_id,
            node_adnl_id,
            expire_at: now + 86400, // 24 hours
            max_size: 1024 * 1024,  // 1 MB
        }
    }

    /// Creates a new certificate builder from a node's public key.
    ///
    /// This convenience method automatically calculates the ADNL short ID from the public key.
    pub fn for_node(overlay_id: [u8; 32], node_public_key: [u8; 32]) -> Self {
        let node_adnl_id = calculate_adnl_short_id(&node_public_key);
        Self::new(overlay_id, node_adnl_id)
    }

    /// Sets the expiration time.
    pub fn expire_at(mut self, expire_at: i32) -> Self {
        self.expire_at = expire_at;
        self
    }

    /// Sets the expiration time to now + duration (in seconds).
    pub fn expire_in(mut self, seconds: i32) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i32;
        self.expire_at = now + seconds;
        self
    }

    /// Sets the maximum broadcast size.
    pub fn max_size(mut self, max_size: i32) -> Self {
        self.max_size = max_size;
        self
    }

    /// Builds and signs the certificate with the issuer's keypair.
    pub fn build(self, issuer: &Ed25519Keypair) -> OverlayCertificate {
        let mut cert = OverlayCertificate::Full {
            issued_by: issuer.public_key,
            expire_at: self.expire_at,
            max_size: self.max_size,
            signature: Vec::new(),
        };

        cert.sign(issuer, &self.overlay_id, &self.node_adnl_id);
        cert
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_certificate() {
        let cert = OverlayCertificate::empty();
        assert!(cert.is_empty());
        assert!(!cert.is_expired());
        assert!(cert.allows_size(1000000));

        let overlay_id = [1u8; 32];
        let node_id = [2u8; 32];
        assert!(cert.validate(&overlay_id, &node_id).is_ok());
    }

    #[test]
    fn test_certificate_roundtrip() {
        let keypair = Ed25519Keypair::generate();
        let overlay_id = [1u8; 32];
        let node_id = [2u8; 32];

        let cert = CertificateBuilder::new(overlay_id, node_id)
            .expire_in(3600)
            .max_size(1024)
            .build(&keypair);

        // Serialize and deserialize
        let tl_data = cert.to_tl();
        let parsed = OverlayCertificate::from_tl(&tl_data).unwrap();

        // Should match
        assert!(!parsed.is_empty());
        assert_eq!(parsed.issued_by(), Some(&keypair.public_key));
        assert_eq!(parsed.max_size(), Some(1024));

        // Should verify
        assert!(parsed.verify(&overlay_id, &node_id).is_ok());
    }

    #[test]
    fn test_empty_certificate_roundtrip() {
        let cert = OverlayCertificate::empty();
        let tl_data = cert.to_tl();
        let parsed = OverlayCertificate::from_tl(&tl_data).unwrap();
        assert!(parsed.is_empty());
    }

    #[test]
    fn test_certificate_verification() {
        let keypair = Ed25519Keypair::generate();
        let overlay_id = [1u8; 32];
        let node_id = [2u8; 32];

        let cert = CertificateBuilder::new(overlay_id, node_id)
            .expire_in(3600)
            .build(&keypair);

        // Should verify with correct IDs
        assert!(cert.verify(&overlay_id, &node_id).is_ok());

        // Should fail with wrong overlay ID
        let wrong_overlay = [99u8; 32];
        assert!(cert.verify(&wrong_overlay, &node_id).is_err());

        // Should fail with wrong node ID
        let wrong_node = [99u8; 32];
        assert!(cert.verify(&overlay_id, &wrong_node).is_err());
    }

    #[test]
    fn test_certificate_expiration() {
        let keypair = Ed25519Keypair::generate();
        let overlay_id = [1u8; 32];
        let node_id = [2u8; 32];

        // Create an already-expired certificate
        let mut cert = OverlayCertificate::Full {
            issued_by: keypair.public_key,
            expire_at: 0, // Expired long ago
            max_size: 1024,
            signature: Vec::new(),
        };
        cert.sign(&keypair, &overlay_id, &node_id);

        assert!(cert.is_expired());
        assert!(cert.validate(&overlay_id, &node_id).is_err());
    }

    #[test]
    fn test_certificate_size_limit() {
        let keypair = Ed25519Keypair::generate();
        let overlay_id = [1u8; 32];
        let node_id = [2u8; 32];

        let cert = CertificateBuilder::new(overlay_id, node_id)
            .max_size(100)
            .build(&keypair);

        assert!(cert.allows_size(50));
        assert!(cert.allows_size(100));
        assert!(!cert.allows_size(101));
    }

    #[test]
    fn test_certificate_builder() {
        let keypair = Ed25519Keypair::generate();
        let overlay_id = [1u8; 32];
        let node_id = [2u8; 32];

        let cert = CertificateBuilder::new(overlay_id, node_id)
            .expire_in(7200)
            .max_size(2048)
            .build(&keypair);

        assert!(!cert.is_empty());
        assert!(!cert.is_expired());
        assert_eq!(cert.max_size(), Some(2048));
        assert!(cert.verify(&overlay_id, &node_id).is_ok());
    }

    #[test]
    fn test_adnl_short_id_calculation() {
        // Verify ADNL short ID is calculated as SHA256 of TL-serialized public key
        let public_key = [0xAB; 32];
        let adnl_id = calculate_adnl_short_id(&public_key);

        // Manually compute expected value
        let mut writer = TlWriter::new();
        writer.write_u32(PUB_ED25519);  // 0x4813b4c6
        writer.write_int256(&public_key);
        let expected = sha256(&writer.finish());

        assert_eq!(adnl_id, expected);
        // ADNL ID should be different from raw public key
        assert_ne!(adnl_id, public_key);
    }

    #[test]
    fn test_certificate_with_public_key() {
        // Test the for_node convenience builder
        let issuer = Ed25519Keypair::generate();
        let node = Ed25519Keypair::generate();
        let overlay_id = [1u8; 32];

        // Build certificate using public key (internally calculates ADNL short ID)
        let cert = CertificateBuilder::for_node(overlay_id, node.public_key)
            .expire_in(3600)
            .max_size(1024)
            .build(&issuer);

        // Verify using public key convenience method
        assert!(cert.verify_for_node(&overlay_id, &node.public_key).is_ok());

        // Should fail with different node's public key
        let other_node = Ed25519Keypair::generate();
        assert!(cert.verify_for_node(&overlay_id, &other_node.public_key).is_err());
    }

    #[test]
    fn test_sign_for_node() {
        let issuer = Ed25519Keypair::generate();
        let node = Ed25519Keypair::generate();
        let overlay_id = [1u8; 32];

        let mut cert = OverlayCertificate::Full {
            issued_by: issuer.public_key,
            expire_at: i32::MAX,
            max_size: 1024,
            signature: Vec::new(),
        };

        // Sign using public key convenience method
        cert.sign_for_node(&issuer, &overlay_id, &node.public_key);

        // Verify using the ADNL short ID
        let node_adnl_id = calculate_adnl_short_id(&node.public_key);
        assert!(cert.verify(&overlay_id, &node_adnl_id).is_ok());
    }
}
