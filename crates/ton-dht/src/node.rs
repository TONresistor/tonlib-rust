//! DHT node types.
//!
//! A DHT node represents a participant in the Kademlia network.
//! Each node has:
//! - A public key (Ed25519) for identification
//! - An address list (IP addresses and ports)
//! - A version number
//! - A signature proving ownership

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::{SystemTime, UNIX_EPOCH};

use ton_crypto::sha256::sha256;

use crate::error::{DhtError, Result};
use crate::tl::{
    TlReader, TlWriter, ADNL_ADDRESS_LIST, ADNL_ADDRESS_UDP, ADNL_ADDRESS_UDP6, DHT_NODE,
    DHT_NODES, PUB_ED25519,
};

/// A node in the DHT network.
#[derive(Debug, Clone)]
pub struct DhtNode {
    /// The node's public key (Ed25519).
    pub id: [u8; 32],
    /// The node's address list.
    pub addr_list: AdnlAddressList,
    /// The version number (usually a timestamp).
    pub version: i32,
    /// The signature proving ownership.
    pub signature: Vec<u8>,
}

impl DhtNode {
    /// Creates a new DHT node.
    pub fn new(id: [u8; 32], addr_list: AdnlAddressList, version: i32) -> Self {
        Self {
            id,
            addr_list,
            version,
            signature: Vec::new(),
        }
    }

    /// Creates a new DHT node with automatic version.
    pub fn with_current_version(id: [u8; 32], addr_list: AdnlAddressList) -> Self {
        let version = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i32)
            .unwrap_or(0);
        Self::new(id, addr_list, version)
    }

    /// Returns the node ID (SHA256 hash of the TL-serialized public key).
    pub fn node_id(&self) -> [u8; 32] {
        let mut writer = TlWriter::new();
        writer.write_u32(PUB_ED25519);
        writer.write_int256(&self.id);
        sha256(&writer.finish())
    }

    /// Signs the node with the given keypair.
    pub fn sign(&mut self, keypair: &ton_crypto::Ed25519Keypair) {
        let to_sign = self.to_tl_for_signing();
        self.signature = keypair.sign(&to_sign).to_vec();
    }

    /// Verifies the signature on this node.
    pub fn verify_signature(&self) -> Result<()> {
        if self.signature.len() != 64 {
            return Err(DhtError::SignatureVerificationFailed(
                "node signature must be 64 bytes".into(),
            ));
        }

        let to_verify = self.to_tl_for_signing();
        let sig: [u8; 64] = self.signature.as_slice().try_into().map_err(|_| {
            DhtError::SignatureVerificationFailed("invalid signature length".into())
        })?;

        ton_crypto::verify_signature(&self.id, &to_verify, &sig).map_err(|e| {
            DhtError::SignatureVerificationFailed(format!("Ed25519 verification failed: {}", e))
        })
    }

    /// Returns the first available socket address, if any.
    pub fn first_addr(&self) -> Option<SocketAddr> {
        self.addr_list.addresses.first().map(|a| a.to_socket_addr())
    }

    /// Serializes the node to TL format.
    pub fn to_tl(&self) -> Vec<u8> {
        let mut writer = TlWriter::new();
        writer.write_u32(DHT_NODE);
        // PublicKey (pub.ed25519)
        writer.write_u32(PUB_ED25519);
        writer.write_int256(&self.id);
        // Address list
        writer.write_raw(&self.addr_list.to_tl());
        // Version
        writer.write_i32(self.version);
        // Signature
        writer.write_bytes(&self.signature);
        writer.finish()
    }

    /// Serializes the node for signing (with zeroed signature).
    fn to_tl_for_signing(&self) -> Vec<u8> {
        let mut writer = TlWriter::new();
        writer.write_u32(DHT_NODE);
        writer.write_u32(PUB_ED25519);
        writer.write_int256(&self.id);
        writer.write_raw(&self.addr_list.to_tl());
        writer.write_i32(self.version);
        // Zero signature for signing/verification
        writer.write_bytes(&[0u8; 64]);
        writer.finish()
    }

    /// Deserializes a node from TL format.
    pub fn from_tl(data: &[u8]) -> Result<Self> {
        let mut reader = TlReader::new(data);
        Self::from_reader(&mut reader)
    }

    /// Deserializes a node from a TL reader.
    pub fn from_reader(reader: &mut TlReader) -> Result<Self> {
        // Check schema ID
        let schema = reader.read_u32()?;
        if schema != DHT_NODE {
            return Err(DhtError::TlError(format!(
                "expected dht.node (0x{:08x}), got 0x{:08x}",
                DHT_NODE, schema
            )));
        }

        // Read PublicKey
        let pub_schema = reader.read_u32()?;
        if pub_schema != PUB_ED25519 {
            return Err(DhtError::TlError(format!(
                "expected pub.ed25519 (0x{:08x}), got 0x{:08x}",
                PUB_ED25519, pub_schema
            )));
        }
        let id = reader.read_int256()?;

        // Read address list
        let addr_list = AdnlAddressList::from_reader(reader)?;

        // Read version
        let version = reader.read_i32()?;

        // Read signature
        let signature = reader.read_bytes()?;

        Ok(Self {
            id,
            addr_list,
            version,
            signature,
        })
    }
}

/// A list of ADNL addresses.
#[derive(Debug, Clone, Default)]
pub struct AdnlAddressList {
    /// The list of addresses.
    pub addresses: Vec<AdnlAddress>,
    /// Version of the address list.
    pub version: i32,
    /// Reinit date for connection handling.
    pub reinit_date: i32,
    /// Priority for address selection.
    pub priority: i32,
    /// Expiration date.
    pub expire_at: i32,
}

impl AdnlAddressList {
    /// Creates a new address list.
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates an address list with a single address.
    pub fn with_address(addr: AdnlAddress) -> Self {
        let version = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i32)
            .unwrap_or(0);
        Self {
            addresses: vec![addr],
            version,
            reinit_date: version,
            priority: 0,
            expire_at: 0,
        }
    }

    /// Creates an address list from a socket address.
    pub fn from_socket_addr(addr: SocketAddr) -> Self {
        Self::with_address(AdnlAddress::from_socket_addr(addr))
    }

    /// Adds an address to the list.
    pub fn add_address(&mut self, addr: AdnlAddress) {
        self.addresses.push(addr);
    }

    /// Serializes the address list to TL format.
    pub fn to_tl(&self) -> Vec<u8> {
        let mut writer = TlWriter::new();
        writer.write_u32(ADNL_ADDRESS_LIST);
        // Vector of addresses
        writer.write_i32(self.addresses.len() as i32);
        for addr in &self.addresses {
            writer.write_raw(&addr.to_tl());
        }
        writer.write_i32(self.version);
        writer.write_i32(self.reinit_date);
        writer.write_i32(self.priority);
        writer.write_i32(self.expire_at);
        writer.finish()
    }

    /// Deserializes an address list from a TL reader.
    pub fn from_reader(reader: &mut TlReader) -> Result<Self> {
        let schema = reader.read_u32()?;
        if schema != ADNL_ADDRESS_LIST {
            return Err(DhtError::TlError(format!(
                "expected adnl.addressList (0x{:08x}), got 0x{:08x}",
                ADNL_ADDRESS_LIST, schema
            )));
        }

        let count = reader.read_i32()? as usize;
        let mut addresses = Vec::with_capacity(count);
        for _ in 0..count {
            addresses.push(AdnlAddress::from_reader(reader)?);
        }

        let version = reader.read_i32()?;
        let reinit_date = reader.read_i32()?;
        let priority = reader.read_i32()?;
        let expire_at = reader.read_i32()?;

        Ok(Self {
            addresses,
            version,
            reinit_date,
            priority,
            expire_at,
        })
    }
}

/// An ADNL network address (UDP or UDP6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AdnlAddress {
    /// IPv4 UDP address.
    Udp { ip: i32, port: i32 },
    /// IPv6 UDP address.
    Udp6 { ip: [u8; 16], port: i32 },
}

impl AdnlAddress {
    /// Creates a UDP address from IPv4.
    pub fn udp(ip: Ipv4Addr, port: u16) -> Self {
        let ip_bytes = ip.octets();
        let ip_i32 = i32::from_be_bytes(ip_bytes);
        Self::Udp {
            ip: ip_i32,
            port: port as i32,
        }
    }

    /// Creates a UDP6 address from IPv6.
    pub fn udp6(ip: Ipv6Addr, port: u16) -> Self {
        Self::Udp6 {
            ip: ip.octets(),
            port: port as i32,
        }
    }

    /// Creates an address from a socket address.
    pub fn from_socket_addr(addr: SocketAddr) -> Self {
        match addr.ip() {
            IpAddr::V4(ip) => Self::udp(ip, addr.port()),
            IpAddr::V6(ip) => Self::udp6(ip, addr.port()),
        }
    }

    /// Converts to a socket address.
    pub fn to_socket_addr(&self) -> SocketAddr {
        match self {
            AdnlAddress::Udp { ip, port } => {
                let ip_bytes = ip.to_be_bytes();
                let ip = Ipv4Addr::new(ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3]);
                SocketAddr::new(IpAddr::V4(ip), *port as u16)
            }
            AdnlAddress::Udp6 { ip, port } => {
                let ip = Ipv6Addr::from(*ip);
                SocketAddr::new(IpAddr::V6(ip), *port as u16)
            }
        }
    }

    /// Serializes the address to TL format.
    pub fn to_tl(&self) -> Vec<u8> {
        let mut writer = TlWriter::new();
        match self {
            AdnlAddress::Udp { ip, port } => {
                writer.write_u32(ADNL_ADDRESS_UDP);
                writer.write_i32(*ip);
                writer.write_i32(*port);
            }
            AdnlAddress::Udp6 { ip, port } => {
                writer.write_u32(ADNL_ADDRESS_UDP6);
                writer.write_raw(ip);
                writer.write_i32(*port);
            }
        }
        writer.finish()
    }

    /// Deserializes an address from a TL reader.
    pub fn from_reader(reader: &mut TlReader) -> Result<Self> {
        let schema = reader.read_u32()?;
        match schema {
            ADNL_ADDRESS_UDP => {
                let ip = reader.read_i32()?;
                let port = reader.read_i32()?;
                Ok(AdnlAddress::Udp { ip, port })
            }
            ADNL_ADDRESS_UDP6 => {
                let ip_bytes = reader.read_raw(16)?;
                let mut ip = [0u8; 16];
                ip.copy_from_slice(ip_bytes);
                let port = reader.read_i32()?;
                Ok(AdnlAddress::Udp6 { ip, port })
            }
            _ => Err(DhtError::TlError(format!(
                "unknown address type: 0x{:08x}",
                schema
            ))),
        }
    }
}

/// A collection of DHT nodes.
#[derive(Debug, Clone, Default)]
pub struct DhtNodes {
    /// The list of nodes.
    pub nodes: Vec<DhtNode>,
}

impl DhtNodes {
    /// Creates a new empty node collection.
    pub fn new() -> Self {
        Self { nodes: Vec::new() }
    }

    /// Creates a node collection from a vector of nodes.
    pub fn from_nodes(nodes: Vec<DhtNode>) -> Self {
        Self { nodes }
    }

    /// Adds a node to the collection.
    pub fn add(&mut self, node: DhtNode) {
        self.nodes.push(node);
    }

    /// Returns the number of nodes.
    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    /// Returns true if empty.
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    /// Serializes the node collection to TL format.
    pub fn to_tl(&self) -> Vec<u8> {
        let mut writer = TlWriter::new();
        writer.write_u32(DHT_NODES);
        writer.write_i32(self.nodes.len() as i32);
        for node in &self.nodes {
            writer.write_raw(&node.to_tl());
        }
        writer.finish()
    }

    /// Deserializes a node collection from TL format.
    pub fn from_tl(data: &[u8]) -> Result<Self> {
        let mut reader = TlReader::new(data);

        let schema = reader.read_u32()?;
        if schema != DHT_NODES {
            return Err(DhtError::TlError(format!(
                "expected dht.nodes (0x{:08x}), got 0x{:08x}",
                DHT_NODES, schema
            )));
        }

        let count = reader.read_i32()? as usize;
        let mut nodes = Vec::with_capacity(count);
        for _ in 0..count {
            nodes.push(DhtNode::from_reader(&mut reader)?);
        }

        Ok(Self { nodes })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ton_crypto::Ed25519Keypair;

    #[test]
    fn test_adnl_address_udp() {
        let addr = AdnlAddress::udp(Ipv4Addr::new(127, 0, 0, 1), 30303);
        let socket = addr.to_socket_addr();

        assert_eq!(socket.ip(), IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
        assert_eq!(socket.port(), 30303);
    }

    #[test]
    fn test_adnl_address_from_socket() {
        let socket: SocketAddr = "192.168.1.1:12345".parse().unwrap();
        let addr = AdnlAddress::from_socket_addr(socket);

        assert_eq!(addr.to_socket_addr(), socket);
    }

    #[test]
    fn test_address_list() {
        let addr = AdnlAddress::udp(Ipv4Addr::new(10, 0, 0, 1), 30303);
        let list = AdnlAddressList::with_address(addr);

        assert_eq!(list.addresses.len(), 1);
        assert_eq!(list.addresses[0], addr);
    }

    #[test]
    fn test_dht_node_creation() {
        let keypair = Ed25519Keypair::generate();
        let addr = AdnlAddress::udp(Ipv4Addr::new(127, 0, 0, 1), 30303);
        let addr_list = AdnlAddressList::with_address(addr);

        let node = DhtNode::with_current_version(keypair.public_key, addr_list);

        assert_eq!(node.id, keypair.public_key);
        assert!(node.version > 0);
    }

    #[test]
    fn test_dht_node_signature() {
        let keypair = Ed25519Keypair::generate();
        let addr = AdnlAddress::udp(Ipv4Addr::new(127, 0, 0, 1), 30303);
        let addr_list = AdnlAddressList::with_address(addr);

        let mut node = DhtNode::with_current_version(keypair.public_key, addr_list);
        node.sign(&keypair);

        assert_eq!(node.signature.len(), 64);
        assert!(node.verify_signature().is_ok());
    }

    #[test]
    fn test_node_id() {
        let keypair = Ed25519Keypair::generate();
        let addr_list = AdnlAddressList::new();
        let node = DhtNode::new(keypair.public_key, addr_list, 0);

        let node_id = node.node_id();
        assert_eq!(node_id.len(), 32);

        // Node ID should be deterministic
        let node_id2 = node.node_id();
        assert_eq!(node_id, node_id2);
    }

    #[test]
    fn test_dht_nodes_collection() {
        let mut nodes = DhtNodes::new();
        assert!(nodes.is_empty());

        let keypair = Ed25519Keypair::generate();
        let addr_list = AdnlAddressList::new();
        let node = DhtNode::new(keypair.public_key, addr_list, 0);

        nodes.add(node);
        assert_eq!(nodes.len(), 1);
    }
}
