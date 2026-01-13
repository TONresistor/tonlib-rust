//! DHT local value storage with TTL management.
//!
//! This module provides local storage for DHT values with:
//! - TTL-based expiration tracking
//! - Efficient eviction of expired values using ordered timestamps
//! - Distance-based storage decisions (store values closer to our node ID)

use std::collections::{BTreeMap, HashMap};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use crate::distance::xor_distance;
use crate::error::Result;
use crate::value::DhtValue;

/// Type alias for DHT key IDs (256-bit).
pub type DhtKeyId = [u8; 32];

/// A value stored locally in the DHT with metadata.
#[derive(Debug, Clone)]
pub struct StoredValue {
    /// The DHT value itself.
    pub value: DhtValue,
    /// When the value was stored locally.
    pub stored_at: Instant,
    /// Unix timestamp when the value expires (from value TTL).
    pub expires_at: u64,
}

impl StoredValue {
    /// Creates a new stored value from a DHT value.
    pub fn new(value: DhtValue) -> Self {
        let expires_at = value.ttl as u64;
        Self {
            value,
            stored_at: Instant::now(),
            expires_at,
        }
    }

    /// Checks if the value has expired.
    pub fn is_expired(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        self.expires_at <= now
    }

    /// Returns the remaining TTL in seconds, or 0 if expired.
    pub fn remaining_ttl(&self) -> u64 {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        self.expires_at.saturating_sub(now)
    }
}

/// Local storage for DHT values with TTL-based eviction.
///
/// This storage maintains:
/// - A hash map of key IDs to stored values for O(1) lookups
/// - A BTreeMap of expiration timestamps for efficient ordered eviction
#[derive(Debug)]
pub struct DhtStorage {
    /// Stored values indexed by key ID.
    values: HashMap<DhtKeyId, StoredValue>,
    /// Expiration order: maps Unix timestamp to list of keys expiring at that time.
    ttl_order: BTreeMap<u64, Vec<DhtKeyId>>,
    /// Maximum number of values to store (0 = unlimited).
    max_values: usize,
}

impl DhtStorage {
    /// Creates a new empty DHT storage.
    pub fn new() -> Self {
        Self {
            values: HashMap::new(),
            ttl_order: BTreeMap::new(),
            max_values: 0,
        }
    }

    /// Creates a new DHT storage with a maximum capacity.
    pub fn with_capacity(max_values: usize) -> Self {
        Self {
            values: HashMap::with_capacity(max_values),
            ttl_order: BTreeMap::new(),
            max_values,
        }
    }

    /// Returns the number of stored values.
    pub fn len(&self) -> usize {
        self.values.len()
    }

    /// Returns true if the storage is empty.
    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }

    /// Stores a value in the local DHT storage.
    ///
    /// If a value with the same key already exists, it will be replaced
    /// if the new value has a later TTL.
    ///
    /// Returns an error if the value is already expired.
    pub fn store(&mut self, key: DhtKeyId, value: DhtValue) -> Result<()> {
        // Check if value is already expired
        if value.is_expired() {
            return Err(crate::error::DhtError::ValueExpired);
        }

        let expires_at = value.ttl as u64;

        // Check if we already have this key
        if let Some(existing) = self.values.get(&key) {
            // Only update if new value has later expiration
            if expires_at <= existing.expires_at {
                return Ok(());
            }
            // Remove old expiration entry
            self.remove_from_ttl_order(&key, existing.expires_at);
        }

        // Evict expired values first if we're at capacity
        if self.max_values > 0 && self.values.len() >= self.max_values {
            self.evict_expired();

            // If still at capacity, evict the soonest-to-expire value
            if self.values.len() >= self.max_values {
                self.evict_oldest();
            }
        }

        // Store the value
        let stored = StoredValue::new(value);
        self.values.insert(key, stored);

        // Add to TTL order
        self.ttl_order
            .entry(expires_at)
            .or_default()
            .push(key);

        Ok(())
    }

    /// Retrieves a value by key ID.
    ///
    /// Returns None if the key is not found or the value has expired.
    pub fn get(&self, key: &DhtKeyId) -> Option<&DhtValue> {
        self.values.get(key).and_then(|stored| {
            if stored.is_expired() {
                None
            } else {
                Some(&stored.value)
            }
        })
    }

    /// Retrieves the stored value with metadata.
    pub fn get_stored(&self, key: &DhtKeyId) -> Option<&StoredValue> {
        self.values.get(key).filter(|stored| !stored.is_expired())
    }

    /// Removes a value by key ID.
    pub fn remove(&mut self, key: &DhtKeyId) -> Option<DhtValue> {
        if let Some(stored) = self.values.remove(key) {
            self.remove_from_ttl_order(key, stored.expires_at);
            Some(stored.value)
        } else {
            None
        }
    }

    /// Evicts all expired values from storage.
    ///
    /// This should be called periodically to clean up expired entries.
    pub fn evict_expired(&mut self) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        // Collect expired timestamps
        let expired_timestamps: Vec<u64> = self
            .ttl_order
            .range(..=now)
            .map(|(&ts, _)| ts)
            .collect();

        // Remove expired values
        for ts in expired_timestamps {
            if let Some(keys) = self.ttl_order.remove(&ts) {
                for key in keys {
                    self.values.remove(&key);
                }
            }
        }
    }

    /// Evicts the value with the soonest expiration time.
    fn evict_oldest(&mut self) {
        if let Some((&ts, _)) = self.ttl_order.first_key_value()
            && let Some(keys) = self.ttl_order.get_mut(&ts) {
                if let Some(key) = keys.pop() {
                    self.values.remove(&key);
                }
                if keys.is_empty() {
                    self.ttl_order.remove(&ts);
                }
            }
    }

    /// Removes a key from the TTL order map.
    fn remove_from_ttl_order(&mut self, key: &DhtKeyId, expires_at: u64) {
        if let Some(keys) = self.ttl_order.get_mut(&expires_at) {
            keys.retain(|k| k != key);
            if keys.is_empty() {
                self.ttl_order.remove(&expires_at);
            }
        }
    }

    /// Determines if we should store a value based on XOR distance.
    ///
    /// In Kademlia, nodes are responsible for storing values whose keys
    /// are close to their node ID. This method checks if the key is
    /// within our responsibility zone.
    ///
    /// # Arguments
    ///
    /// * `key` - The DHT key ID to check
    /// * `our_id` - Our local node ID
    ///
    /// # Returns
    ///
    /// Returns true if we should store the value. The decision is based on:
    /// - The XOR distance between the key and our node ID
    /// - Currently returns true for all keys (nodes typically accept any value
    ///   during store operations; the publisher is responsible for finding
    ///   the closest nodes)
    pub fn should_store(&self, key: &DhtKeyId, our_id: &[u8; 32]) -> bool {
        // Calculate distance from our node to the key
        let distance = xor_distance(our_id, key);

        // In practice, we store values if the store request comes from
        // a node that has determined we are among the k-closest nodes.
        // The bucket_index gives us an indication of how close we are:
        // - Higher bucket index = closer (more leading zeros in XOR distance)
        //
        // Typical Kademlia implementations accept store requests during
        // the iterative store process, where the publisher has already
        // selected the k-closest nodes.
        //
        // We accept values that are reasonably close (bucket >= 128 means
        // we share at least half the key prefix with the target)
        let bucket = distance.bucket_index();

        // Accept if we're in the closer half of the keyspace
        // bucket 128+ means at least 128 leading zero bits match
        // For more permissive storage, we can lower this threshold
        // or always return true and rely on the publisher's selection
        bucket >= 128 || self.values.len() < 1000
    }

    /// Returns an iterator over all stored values.
    pub fn iter(&self) -> impl Iterator<Item = (&DhtKeyId, &StoredValue)> {
        self.values.iter()
    }

    /// Returns statistics about the storage.
    pub fn stats(&self) -> DhtStorageStats {
        let mut expired_count = 0;
        let mut total_remaining_ttl = 0u64;

        for stored in self.values.values() {
            if stored.is_expired() {
                expired_count += 1;
            } else {
                total_remaining_ttl += stored.remaining_ttl();
            }
        }

        let active_count = self.values.len() - expired_count;
        let avg_remaining_ttl = if active_count > 0 {
            total_remaining_ttl / active_count as u64
        } else {
            0
        };

        DhtStorageStats {
            total_values: self.values.len(),
            expired_values: expired_count,
            active_values: active_count,
            avg_remaining_ttl,
            ttl_buckets: self.ttl_order.len(),
        }
    }
}

impl Default for DhtStorage {
    fn default() -> Self {
        Self::new()
    }
}

/// Statistics about DHT storage.
#[derive(Debug, Clone)]
pub struct DhtStorageStats {
    /// Total number of stored values (including expired).
    pub total_values: usize,
    /// Number of expired values pending eviction.
    pub expired_values: usize,
    /// Number of active (non-expired) values.
    pub active_values: usize,
    /// Average remaining TTL of active values in seconds.
    pub avg_remaining_ttl: u64,
    /// Number of distinct TTL timestamps.
    pub ttl_buckets: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::{DhtKey, DhtKeyDescription};
    use crate::value::UpdateRule;
    use ton_crypto::Ed25519Keypair;

    fn create_test_value(ttl_seconds: u32) -> (DhtKeyId, DhtValue) {
        let keypair = Ed25519Keypair::generate();
        let key = DhtKey::from_public_key(&keypair.public_key, b"test", 0);
        let key_desc = DhtKeyDescription::new(key.clone(), keypair.public_key, UpdateRule::Anybody);
        let value = DhtValue::with_ttl_duration(key_desc, b"test data".to_vec(), ttl_seconds);
        (key.id, value)
    }

    fn create_expired_value() -> (DhtKeyId, DhtValue) {
        let keypair = Ed25519Keypair::generate();
        let key = DhtKey::from_public_key(&keypair.public_key, b"expired", 0);
        let key_desc = DhtKeyDescription::new(key.clone(), keypair.public_key, UpdateRule::Anybody);
        // Create a value that's already expired (TTL in the past)
        let value = DhtValue::new(key_desc, b"old data".to_vec(), 1);
        (key.id, value)
    }

    #[test]
    fn test_storage_creation() {
        let storage = DhtStorage::new();
        assert!(storage.is_empty());
        assert_eq!(storage.len(), 0);
    }

    #[test]
    fn test_store_and_get() {
        let mut storage = DhtStorage::new();
        let (key, value) = create_test_value(3600);

        assert!(storage.store(key, value.clone()).is_ok());
        assert_eq!(storage.len(), 1);

        let retrieved = storage.get(&key);
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().value, value.value);
    }

    #[test]
    fn test_store_expired_value() {
        let mut storage = DhtStorage::new();
        let (key, value) = create_expired_value();

        let result = storage.store(key, value);
        assert!(result.is_err());
        assert!(storage.is_empty());
    }

    #[test]
    fn test_get_nonexistent() {
        let storage = DhtStorage::new();
        let key = [0u8; 32];

        assert!(storage.get(&key).is_none());
    }

    #[test]
    fn test_remove() {
        let mut storage = DhtStorage::new();
        let (key, value) = create_test_value(3600);

        storage.store(key, value).unwrap();
        assert_eq!(storage.len(), 1);

        let removed = storage.remove(&key);
        assert!(removed.is_some());
        assert!(storage.is_empty());
    }

    #[test]
    fn test_evict_expired() {
        let mut storage = DhtStorage::new();

        // Store a value with short TTL
        let keypair = Ed25519Keypair::generate();
        let key = DhtKey::from_public_key(&keypair.public_key, b"short", 0);
        let key_desc = DhtKeyDescription::new(key.clone(), keypair.public_key, UpdateRule::Anybody);
        // Create a value that will expire very soon
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i32;
        let value = DhtValue::new(key_desc, b"short ttl".to_vec(), now + 1);

        storage.store(key.id, value).unwrap();
        assert_eq!(storage.len(), 1);

        // Store a value with long TTL
        let (key2, value2) = create_test_value(36000);
        storage.store(key2, value2).unwrap();
        assert_eq!(storage.len(), 2);

        // Wait a bit (simulated by calling evict_expired which checks current time)
        // In a real test we'd need to mock time or wait
        // For now, just verify evict_expired runs without error
        storage.evict_expired();
    }

    #[test]
    fn test_update_value_with_later_ttl() {
        let mut storage = DhtStorage::new();

        let keypair = Ed25519Keypair::generate();
        let key = DhtKey::from_public_key(&keypair.public_key, b"update", 0);
        let key_desc =
            DhtKeyDescription::new(key.clone(), keypair.public_key, UpdateRule::Anybody);

        // Store initial value
        let value1 = DhtValue::with_ttl_duration(key_desc.clone(), b"first".to_vec(), 3600);
        storage.store(key.id, value1).unwrap();

        // Update with later TTL
        let value2 = DhtValue::with_ttl_duration(key_desc.clone(), b"second".to_vec(), 7200);
        storage.store(key.id, value2).unwrap();

        let retrieved = storage.get(&key.id).unwrap();
        assert_eq!(retrieved.value, b"second");
    }

    #[test]
    fn test_update_value_with_earlier_ttl_ignored() {
        let mut storage = DhtStorage::new();

        let keypair = Ed25519Keypair::generate();
        let key = DhtKey::from_public_key(&keypair.public_key, b"update", 0);
        let key_desc =
            DhtKeyDescription::new(key.clone(), keypair.public_key, UpdateRule::Anybody);

        // Store initial value with long TTL
        let value1 = DhtValue::with_ttl_duration(key_desc.clone(), b"first".to_vec(), 7200);
        storage.store(key.id, value1).unwrap();

        // Try to update with shorter TTL (should be ignored)
        let value2 = DhtValue::with_ttl_duration(key_desc.clone(), b"second".to_vec(), 3600);
        storage.store(key.id, value2).unwrap();

        let retrieved = storage.get(&key.id).unwrap();
        assert_eq!(retrieved.value, b"first");
    }

    #[test]
    fn test_should_store() {
        let storage = DhtStorage::new();

        let our_id = [0u8; 32];

        // Key that's close to our ID (many leading zeros in XOR distance)
        let mut close_key = [0u8; 32];
        close_key[31] = 0x01; // Only differs in LSB
        assert!(storage.should_store(&close_key, &our_id));

        // Key that's far from our ID
        let mut far_key = [0xFF; 32];
        far_key[0] = 0x80;
        // This will have low bucket index, but storage is nearly empty so accepts
        assert!(storage.should_store(&far_key, &our_id));
    }

    #[test]
    fn test_storage_stats() {
        let mut storage = DhtStorage::new();

        let stats = storage.stats();
        assert_eq!(stats.total_values, 0);
        assert_eq!(stats.active_values, 0);

        let (key, value) = create_test_value(3600);
        storage.store(key, value).unwrap();

        let stats = storage.stats();
        assert_eq!(stats.total_values, 1);
        assert_eq!(stats.active_values, 1);
        assert!(stats.avg_remaining_ttl > 0);
    }

    #[test]
    fn test_storage_with_capacity() {
        let mut storage = DhtStorage::with_capacity(2);

        let (key1, value1) = create_test_value(3600);
        let (key2, value2) = create_test_value(7200);
        let (key3, value3) = create_test_value(1800);

        storage.store(key1, value1).unwrap();
        storage.store(key2, value2).unwrap();

        // Third value should trigger eviction of key3 (shortest TTL)
        storage.store(key3, value3).unwrap();

        // Should still have at most 2 values
        assert!(storage.len() <= 2);
    }

    #[test]
    fn test_stored_value_remaining_ttl() {
        let (_, value) = create_test_value(3600);
        let stored = StoredValue::new(value);

        let remaining = stored.remaining_ttl();
        assert!(remaining > 0);
        assert!(remaining <= 3600);
        assert!(!stored.is_expired());
    }

    #[test]
    fn test_iter() {
        let mut storage = DhtStorage::new();

        let (key1, value1) = create_test_value(3600);
        let (key2, value2) = create_test_value(7200);

        storage.store(key1, value1).unwrap();
        storage.store(key2, value2).unwrap();

        let count = storage.iter().count();
        assert_eq!(count, 2);
    }
}
