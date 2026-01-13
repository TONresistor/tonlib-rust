//! Configuration for DHT bootstrap nodes.
//!
//! This module provides bootstrap node configurations for TON mainnet and testnet.
//! Bootstrap nodes are well-known DHT nodes that help new nodes discover the network.

use std::net::SocketAddr;

use crate::error::Result;
use crate::node::{AdnlAddress, AdnlAddressList, DhtNode};

/// Network type for bootstrap configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Network {
    /// TON mainnet
    Mainnet,
    /// TON testnet
    Testnet,
}

/// Bootstrap node configuration entry: (address, port, public_key_hex)
type BootstrapNodeConfig = (&'static str, u16, &'static str);

/// Mainnet bootstrap nodes from official TON configuration
/// https://ton.org/global-config.json
pub const MAINNET_BOOTSTRAP_NODES: &[BootstrapNodeConfig] = &[
    ("135.181.140.211", 30303, "e818a5edee3201e7191bfc6b62e7ada9e9268dc237c12b05250ffc35611cd279"),
    ("135.181.140.212", 30303, "bfa0579d1c613fc1ecf2e4d00947dbba673d8f630acf822eca3cf00121344ba2"),
    ("135.181.140.213", 30303, "43caf061ae20352b2fe49f80d21194b164f86a0f2dbcbe3142eade7d26ed95e0"),
];

/// Testnet bootstrap nodes
pub const TESTNET_BOOTSTRAP_NODES: &[BootstrapNodeConfig] = &[
    ("37.19.192.100", 30303, "066bb1ae3c956d10db2a0eba65de6faaadb3133e68f86b90aa7e76356ff2510e"),
    ("37.19.192.101", 30303, "ed818bec005a4d42fc934e997a0c8bfcdac8d3353f0a1edd1b51e9ed23f0f6b4"),
];

/// Parses bootstrap node configuration entries into DhtNode instances.
fn parse_bootstrap_nodes(configs: &[BootstrapNodeConfig]) -> Result<Vec<DhtNode>> {
    let mut nodes = Vec::new();

    for (addr_str, port, pubkey_hex) in configs {
        // Parse the public key from hex
        let pubkey = parse_hex_key(pubkey_hex)?;

        // Create the socket address
        let addr: SocketAddr = format!("{}:{}", addr_str, port)
            .parse()
            .map_err(|_| crate::error::DhtError::InvalidNode(
                format!("Invalid bootstrap node address: {}:{}", addr_str, port)
            ))?;

        // Create an ADNL address
        let adnl_addr = AdnlAddress::from_socket_addr(addr);

        let addr_list = AdnlAddressList::with_address(adnl_addr);

        // Create the DHT node
        let node = DhtNode::with_current_version(pubkey, addr_list);
        nodes.push(node);
    }

    Ok(nodes)
}

/// Parses a hexadecimal string into a 32-byte public key.
fn parse_hex_key(hex_str: &str) -> Result<[u8; 32]> {
    if hex_str.len() != 64 {
        return Err(crate::error::DhtError::InvalidNode(
            format!("Invalid hex key length: expected 64 chars, got {}", hex_str.len())
        ));
    }

    let mut key = [0u8; 32];
    for (i, chunk) in hex_str.as_bytes().chunks(2).enumerate() {
        let hex_byte = std::str::from_utf8(chunk)
            .ok()
            .and_then(|s| u8::from_str_radix(s, 16).ok())
            .ok_or_else(|| crate::error::DhtError::InvalidNode(
                format!("Invalid hex character in key at position {}", i * 2)
            ))?;
        key[i] = hex_byte;
    }

    Ok(key)
}

/// Returns the bootstrap nodes for the specified network.
pub fn get_bootstrap_nodes(network: Network) -> Result<Vec<DhtNode>> {
    match network {
        Network::Mainnet => parse_bootstrap_nodes(MAINNET_BOOTSTRAP_NODES),
        Network::Testnet => parse_bootstrap_nodes(TESTNET_BOOTSTRAP_NODES),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_hex_key_valid() {
        let hex = "e818a5edee3201e7191bfc6b62e7ada9e9268dc237c12b05250ffc35611cd279";
        let key = parse_hex_key(hex).unwrap();
        assert_eq!(key.len(), 32);
        assert_eq!(key[0], 0xe8);
        assert_eq!(key[1], 0x18);
    }

    #[test]
    fn test_parse_hex_key_invalid_length() {
        let hex = "e818a5edee3201e7191bfc6b62e7ada9e9268dc237c12b05250ffc35611cd27"; // 63 chars instead of 64
        assert!(parse_hex_key(hex).is_err());
    }

    #[test]
    fn test_parse_hex_key_invalid_chars() {
        let hex = "g818a5edee3201e7191bfc6b62e7ada9e9268dc237c12b05250ffc35611cd279";
        assert!(parse_hex_key(hex).is_err());
    }

    #[test]
    fn test_mainnet_bootstrap_config() {
        assert!(!MAINNET_BOOTSTRAP_NODES.is_empty());
        for (addr, port, pubkey) in MAINNET_BOOTSTRAP_NODES {
            assert!(!addr.is_empty());
            assert!(*port > 0);
            assert_eq!(pubkey.len(), 64); // hex string should be 64 chars
        }
    }

    #[test]
    fn test_testnet_bootstrap_config() {
        assert!(!TESTNET_BOOTSTRAP_NODES.is_empty());
        for (addr, port, pubkey) in TESTNET_BOOTSTRAP_NODES {
            assert!(!addr.is_empty());
            assert!(*port > 0);
            assert_eq!(pubkey.len(), 64); // hex string should be 64 chars
        }
    }

    #[test]
    fn test_get_mainnet_bootstrap_nodes() {
        let result = get_bootstrap_nodes(Network::Mainnet);
        assert!(result.is_ok());
        let nodes = result.unwrap();
        assert_eq!(nodes.len(), MAINNET_BOOTSTRAP_NODES.len());
    }

    #[test]
    fn test_get_testnet_bootstrap_nodes() {
        let result = get_bootstrap_nodes(Network::Testnet);
        assert!(result.is_ok());
        let nodes = result.unwrap();
        assert_eq!(nodes.len(), TESTNET_BOOTSTRAP_NODES.len());
    }
}
