//! Highload Wallet V2R2 for mass transfers
//!
//! This wallet supports up to 254 transfers in a single transaction
//! using a HashmapE(16) dictionary structure.

use crate::codes::highload_v2r2_code;
use crate::error::{WalletError, WalletResult};
use crate::transfer::Transfer;
use crate::wallet::Wallet;
use std::collections::BTreeMap;
use std::sync::Arc;
use ton_cell::{Cell, CellBuilder, MsgAddress};
use ton_crypto::Ed25519Keypair;

/// Highload Wallet V2 revision 2
/// Supports up to 254 transfers in a single transaction
pub struct HighloadV2R2 {
    keypair: Ed25519Keypair,
    workchain: i32,
    subwallet_id: u32,
    address: MsgAddress,
}

impl HighloadV2R2 {
    /// Maximum transfers per transaction
    pub const MAX_TRANSFERS: usize = 254;

    /// Key bit length for HashmapE
    const KEY_BITS: usize = 16;

    /// Query timeout in seconds (per official TON specification)
    /// Queries older than this are considered expired
    pub const QUERY_TIMEOUT: u64 = 65536; // ~18.2 hours

    /// Create new highload wallet
    pub fn new(keypair: Ed25519Keypair, workchain: i32) -> WalletResult<Self> {
        let subwallet_id = 698983191 + workchain as u32;
        Self::with_subwallet(keypair, workchain, subwallet_id)
    }

    /// Create with custom subwallet ID
    pub fn with_subwallet(
        keypair: Ed25519Keypair,
        workchain: i32,
        subwallet_id: u32,
    ) -> WalletResult<Self> {
        let address = Self::calculate_address(&keypair.public_key, workchain, subwallet_id)?;
        Ok(Self {
            keypair,
            workchain,
            subwallet_id,
            address,
        })
    }

    /// Calculate wallet address
    pub fn calculate_address(
        pubkey: &[u8; 32],
        workchain: i32,
        subwallet_id: u32,
    ) -> WalletResult<MsgAddress> {
        let state_init = Self::create_state_init_static(pubkey, subwallet_id)?;
        let hash = state_init.hash();
        Ok(MsgAddress::Internal {
            workchain,
            address: hash,
        })
    }

    fn create_state_init_static(pubkey: &[u8; 32], subwallet_id: u32) -> WalletResult<Cell> {
        let code = highload_v2r2_code()?;

        // Data: subwallet_id:32 last_cleaned:64 public_key:256 queries:dict
        let mut data_builder = CellBuilder::new();
        data_builder.store_u32(subwallet_id)?;
        data_builder.store_u64(0)?;
        data_builder.store_bytes(pubkey)?;
        data_builder.store_bit(false)?;
        let data = data_builder.build()?;

        let mut si_builder = CellBuilder::new();
        si_builder.store_bit(false)?;
        si_builder.store_bit(false)?;
        si_builder.store_bit(true)?;
        si_builder.store_ref(code)?;
        si_builder.store_bit(true)?;
        si_builder.store_ref(Arc::new(data))?;
        si_builder.store_bit(false)?;
        si_builder.build().map_err(Into::into)
    }

    /// Create batch transfer body with query ID
    ///
    /// The query_id encodes a timestamp in its upper 32 bits. This function validates
    /// that the query is not expired according to the TON specification (65536 seconds timeout).
    pub fn create_batch_transfer_body(
        &self,
        query_id: u64,
        transfers: &[Transfer],
        _valid_until: u32,
    ) -> WalletResult<Cell> {
        use std::time::{SystemTime, UNIX_EPOCH};

        // Validate query_id timestamp (upper 32 bits contain Unix timestamp)
        let query_time = query_id >> 32;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Reject expired queries per TON specification
        if now > query_time + Self::QUERY_TIMEOUT {
            return Err(WalletError::MessageExpired);
        }

        if transfers.len() > Self::MAX_TRANSFERS {
            return Err(WalletError::TooManyTransfers {
                max: Self::MAX_TRANSFERS,
                got: transfers.len(),
            });
        }

        // Build messages dictionary (HashmapE with 16-bit keys)
        let messages_dict = self.build_messages_hashmap(transfers)?;

        // Body: subwallet_id:32 query_id:64 messages:dict
        let mut builder = CellBuilder::new();
        builder.store_u32(self.subwallet_id)?;
        builder.store_u64(query_id)?;
        builder.store_bit(true)?; // has dict
        builder.store_ref(Arc::new(messages_dict))?;
        builder.build().map_err(Into::into)
    }

    /// Build a HashmapE(16) from transfers
    ///
    /// HashmapE is a patricia trie where:
    /// - hme_empty$0 = HashmapE n X (empty)
    /// - hme_root$1 {n:#} {X:Type} root:^(Hashmap n X) = HashmapE n X (non-empty)
    ///
    /// Hashmap nodes:
    /// - hm_edge {n:#} {X:Type} {l:#} {m:#} label:(HmLabel ~l n) {n = (~m) + l}
    ///   node:(HashmapNode m X) = Hashmap n X
    ///
    /// HashmapNode:
    /// - hmn_leaf {X:Type} value:X = HashmapNode 0 X
    /// - hmn_fork {n:#} {X:Type} left:^(Hashmap n X) right:^(Hashmap n X) = HashmapNode (n+1) X
    fn build_messages_hashmap(&self, transfers: &[Transfer]) -> WalletResult<Cell> {
        if transfers.is_empty() {
            // Empty hashmap: just return empty cell
            return CellBuilder::new().build().map_err(Into::into);
        }

        // Build key-value map
        let mut entries: BTreeMap<u16, Cell> = BTreeMap::new();
        for (i, transfer) in transfers.iter().enumerate() {
            let msg = self.build_internal_message(transfer)?;
            // Value: mode:uint8 ^MessageRelaxed
            let mut value_builder = CellBuilder::new();
            value_builder.store_u8(transfer.mode)?;
            value_builder.store_ref(Arc::new(msg))?;
            entries.insert(i as u16, value_builder.build()?);
        }

        // Build the patricia trie
        self.build_hashmap_node(&entries, 0, Self::KEY_BITS)
    }

    /// Recursively build a hashmap node for a range of keys
    fn build_hashmap_node(
        &self,
        entries: &BTreeMap<u16, Cell>,
        prefix: u16,
        remaining_bits: usize,
    ) -> WalletResult<Cell> {
        // Filter entries that match current prefix
        let mask = if remaining_bits >= 16 {
            0
        } else {
            !((1u16 << remaining_bits) - 1)
        };

        let matching: Vec<(&u16, &Cell)> = entries
            .iter()
            .filter(|(k, _)| (*k & mask) == (prefix & mask))
            .collect();

        if matching.is_empty() {
            return CellBuilder::new().build().map_err(Into::into);
        }

        if matching.len() == 1 && remaining_bits > 0 {
            // Single entry - create leaf with label
            let (&key, value) = matching[0];
            return self.build_leaf_edge(key, prefix, remaining_bits, value);
        }

        if remaining_bits == 0 {
            // Leaf node - just the value
            let (_, value) = matching[0];
            return Ok(value.clone());
        }

        // Fork node - split into left (0) and right (1) branches
        let half_bit = 1u16 << (remaining_bits - 1);

        let left_prefix = prefix;
        let right_prefix = prefix | half_bit;

        let left_entries: BTreeMap<u16, Cell> = entries
            .iter()
            .filter(|(k, _)| (*k & half_bit) == 0)
            .map(|(k, v)| (*k, v.clone()))
            .collect();

        let right_entries: BTreeMap<u16, Cell> = entries
            .iter()
            .filter(|(k, _)| (*k & half_bit) != 0)
            .map(|(k, v)| (*k, v.clone()))
            .collect();

        // Build fork node
        let mut builder = CellBuilder::new();

        if !left_entries.is_empty() && !right_entries.is_empty() {
            // Both branches exist - create fork
            let left = self.build_hashmap_node(&left_entries, left_prefix, remaining_bits - 1)?;
            let right = self.build_hashmap_node(&right_entries, right_prefix, remaining_bits - 1)?;

            // hm_edge with empty label (short form: label_short$0 0)
            builder.store_bit(false)?; // label_short
            builder.store_bit(false)?; // length = 0

            // Fork node: left and right refs
            builder.store_ref(Arc::new(left))?;
            builder.store_ref(Arc::new(right))?;
        } else if !left_entries.is_empty() {
            // Only left branch - need edge with label
            return self.build_edge_with_label(&left_entries, left_prefix, remaining_bits, false);
        } else {
            // Only right branch - need edge with label
            return self.build_edge_with_label(&right_entries, right_prefix, remaining_bits, true);
        }

        builder.build().map_err(Into::into)
    }

    /// Build an edge with a label pointing to a subtree
    fn build_edge_with_label(
        &self,
        entries: &BTreeMap<u16, Cell>,
        prefix: u16,
        remaining_bits: usize,
        is_right: bool,
    ) -> WalletResult<Cell> {
        let mut builder = CellBuilder::new();

        // Store 1-bit label for the direction
        builder.store_bit(false)?; // label_short
        builder.store_bit(true)?; // length = 1
        builder.store_bit(is_right)?; // the bit value

        // Build child node
        let child = self.build_hashmap_node(entries, prefix, remaining_bits - 1)?;

        if child.reference_count() > 0 || child.bit_len() > 0 {
            builder.store_ref(Arc::new(child))?;
        }

        builder.build().map_err(Into::into)
    }

    /// Build a leaf edge (edge directly to value with full remaining key as label)
    fn build_leaf_edge(
        &self,
        key: u16,
        _prefix: u16,
        remaining_bits: usize,
        value: &Cell,
    ) -> WalletResult<Cell> {
        let mut builder = CellBuilder::new();

        if remaining_bits == 0 {
            // No label needed, just copy value
            let data = value.data();
            for i in 0..value.bit_len() {
                let byte_idx = i / 8;
                let bit_idx = 7 - (i % 8);
                let bit = (data[byte_idx] >> bit_idx) & 1 == 1;
                builder.store_bit(bit)?;
            }
            for r in value.references() {
                builder.store_ref(r.clone())?;
            }
        } else if remaining_bits <= 6 {
            // Short label: label_short$0 len:(#<= m) s:(bits len)
            // where m = remaining_bits
            builder.store_bit(false)?; // label_short

            // Unary encode length
            for _ in 0..remaining_bits {
                builder.store_bit(true)?;
            }
            builder.store_bit(false)?; // terminator

            // Store the key bits
            for i in 0..remaining_bits {
                let bit = (key >> (remaining_bits - 1 - i)) & 1 == 1;
                builder.store_bit(bit)?;
            }

            // Store value inline
            let data = value.data();
            for i in 0..value.bit_len() {
                let byte_idx = i / 8;
                let bit_idx = 7 - (i % 8);
                let bit = (data[byte_idx] >> bit_idx) & 1 == 1;
                builder.store_bit(bit)?;
            }
            for r in value.references() {
                builder.store_ref(r.clone())?;
            }
        } else {
            // Long label: label_long$10 len:(#<= m) s:(bits len)
            builder.store_bit(true)?; // label_long prefix
            builder.store_bit(false)?; // label_long

            // Store length as bits (ceil(log2(remaining_bits+1)))
            let len_bits = 16 - (remaining_bits as u16).leading_zeros() as usize;
            for i in 0..len_bits {
                let bit = (remaining_bits >> (len_bits - 1 - i)) & 1 == 1;
                builder.store_bit(bit)?;
            }

            // Store the key bits
            for i in 0..remaining_bits {
                let bit = (key >> (remaining_bits - 1 - i)) & 1 == 1;
                builder.store_bit(bit)?;
            }

            // Store value inline
            let data = value.data();
            for i in 0..value.bit_len() {
                let byte_idx = i / 8;
                let bit_idx = 7 - (i % 8);
                let bit = (data[byte_idx] >> bit_idx) & 1 == 1;
                builder.store_bit(bit)?;
            }
            for r in value.references() {
                builder.store_ref(r.clone())?;
            }
        }

        builder.build().map_err(Into::into)
    }

    fn build_internal_message(&self, transfer: &Transfer) -> WalletResult<Cell> {
        let mut builder = CellBuilder::new();

        builder.store_bit(false)?;
        builder.store_bit(true)?;
        builder.store_bit(transfer.bounce)?;
        builder.store_bit(false)?;

        builder.store_bits(&[false, false])?;
        builder.store_address(&transfer.to)?;
        builder.store_coins(transfer.amount)?;
        builder.store_bit(false)?;

        builder.store_coins(0)?;
        builder.store_coins(0)?;
        builder.store_u64(0)?;
        builder.store_u32(0)?;

        builder.store_bit(false)?;

        if let Some(ref payload) = transfer.payload {
            builder.store_bit(true)?;
            builder.store_ref(payload.clone())?;
        } else {
            builder.store_bit(false)?;
        }

        builder.build().map_err(Into::into)
    }

    /// Generate a unique query ID
    pub fn generate_query_id() -> u64 {
        use std::time::{SystemTime, UNIX_EPOCH};
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        (now << 32) | (rand::random::<u32>() as u64)
    }
}

impl Wallet for HighloadV2R2 {
    fn version(&self) -> &'static str {
        "highload_v2r2"
    }

    fn address(&self) -> &MsgAddress {
        &self.address
    }

    fn public_key(&self) -> &[u8; 32] {
        &self.keypair.public_key
    }

    fn workchain(&self) -> i32 {
        self.workchain
    }

    fn state_init(&self) -> WalletResult<Cell> {
        Self::create_state_init_static(&self.keypair.public_key, self.subwallet_id)
    }

    fn create_transfer_body(
        &self,
        _seqno: u32,
        transfers: &[Transfer],
        _valid_until: u32,
    ) -> WalletResult<Cell> {
        let query_id = Self::generate_query_id();
        self.create_batch_transfer_body(query_id, transfers, u32::MAX)
    }

    fn sign(&self, body: &Cell) -> WalletResult<Cell> {
        let body_hash = body.hash();
        let signature = self.keypair.sign(&body_hash);

        let mut builder = CellBuilder::new();
        builder.store_bytes(&signature)?;

        let body_data = body.data();
        for i in 0..body.bit_len() {
            let byte_idx = i / 8;
            let bit_idx = 7 - (i % 8);
            let bit = (body_data[byte_idx] >> bit_idx) & 1 == 1;
            builder.store_bit(bit)?;
        }

        for r in body.references() {
            builder.store_ref(r.clone())?;
        }

        builder.build().map_err(Into::into)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_highload() {
        let keypair = Ed25519Keypair::generate();
        let wallet = HighloadV2R2::new(keypair, 0).unwrap();
        assert_eq!(wallet.version(), "highload_v2r2");
    }

    #[test]
    fn test_single_transfer() {
        let keypair = Ed25519Keypair::generate();
        let wallet = HighloadV2R2::new(keypair, 0).unwrap();

        let transfers = vec![Transfer::new(MsgAddress::Null, 1_000_000_000)];
        let query_id = HighloadV2R2::generate_query_id();

        let body = wallet
            .create_batch_transfer_body(query_id, &transfers, u32::MAX)
            .unwrap();
        assert!(body.bit_len() > 0);
    }

    #[test]
    fn test_batch_transfer_small() {
        let keypair = Ed25519Keypair::generate();
        let wallet = HighloadV2R2::new(keypair, 0).unwrap();

        let transfers: Vec<Transfer> = (0..10)
            .map(|_| Transfer::new(MsgAddress::Null, 1_000_000_000))
            .collect();
        let query_id = HighloadV2R2::generate_query_id();

        let body = wallet
            .create_batch_transfer_body(query_id, &transfers, u32::MAX)
            .unwrap();
        assert!(body.bit_len() > 0);
    }

    #[test]
    fn test_batch_transfer_medium() {
        let keypair = Ed25519Keypair::generate();
        let wallet = HighloadV2R2::new(keypair, 0).unwrap();

        // Test with 50 transfers using HashmapE
        let transfers: Vec<Transfer> = (0..50)
            .map(|_| Transfer::new(MsgAddress::Null, 1_000_000_000))
            .collect();
        let query_id = HighloadV2R2::generate_query_id();

        let body = wallet
            .create_batch_transfer_body(query_id, &transfers, u32::MAX)
            .unwrap();
        assert!(body.bit_len() > 0);
    }

    #[test]
    fn test_batch_transfer_max() {
        let keypair = Ed25519Keypair::generate();
        let wallet = HighloadV2R2::new(keypair, 0).unwrap();

        // Test with maximum 254 transfers
        let transfers: Vec<Transfer> = (0..254)
            .map(|_| Transfer::new(MsgAddress::Null, 1_000_000_000))
            .collect();
        let query_id = HighloadV2R2::generate_query_id();

        let body = wallet
            .create_batch_transfer_body(query_id, &transfers, u32::MAX)
            .unwrap();
        assert!(body.bit_len() > 0);
    }

    #[test]
    fn test_max_transfers_exceeded() {
        let keypair = Ed25519Keypair::generate();
        let wallet = HighloadV2R2::new(keypair, 0).unwrap();

        let transfers: Vec<Transfer> = (0..255)
            .map(|_| Transfer::new(MsgAddress::Null, 1_000_000_000))
            .collect();
        let query_id = HighloadV2R2::generate_query_id();

        let result = wallet.create_batch_transfer_body(query_id, &transfers, u32::MAX);
        assert!(matches!(result, Err(WalletError::TooManyTransfers { .. })));
    }

    #[test]
    fn test_query_id_generation() {
        let q1 = HighloadV2R2::generate_query_id();
        let q2 = HighloadV2R2::generate_query_id();
        assert_ne!(q1, q2);
    }

    #[test]
    fn test_expired_query_id_rejected() {
        let keypair = Ed25519Keypair::generate();
        let wallet = HighloadV2R2::new(keypair, 0).unwrap();

        // Create an expired query_id (timestamp from 2020, way past timeout)
        let old_timestamp: u64 = 1577836800; // Jan 1, 2020
        let expired_query_id = (old_timestamp << 32) | 12345;

        let transfers = vec![Transfer::new(MsgAddress::Null, 1_000_000_000)];

        let result = wallet.create_batch_transfer_body(expired_query_id, &transfers, u32::MAX);
        assert!(
            matches!(result, Err(WalletError::MessageExpired)),
            "Expired query_id should be rejected"
        );
    }

    #[test]
    fn test_valid_query_id_accepted() {
        let keypair = Ed25519Keypair::generate();
        let wallet = HighloadV2R2::new(keypair, 0).unwrap();

        // Use a fresh query_id (current timestamp)
        let valid_query_id = HighloadV2R2::generate_query_id();

        let transfers = vec![Transfer::new(MsgAddress::Null, 1_000_000_000)];

        let result = wallet.create_batch_transfer_body(valid_query_id, &transfers, u32::MAX);
        assert!(result.is_ok(), "Valid query_id should be accepted");
    }
}
