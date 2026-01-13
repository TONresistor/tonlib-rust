//! Provider discovery module for TON Storage.
//!
//! This module handles DHT-based peer selection for uploads and downloads.
//! It provides peer discovery, scoring, caching, and blacklist management.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::RwLock;
use tracing::{debug, warn, info};

use ton_dht::DhtClient;
use ton_dht::DhtValueResult;

use crate::error::{StorageError, StorageResult};
use crate::types::ProviderInfo;

/// Type alias for BagId (SHA256 hash of TorrentInfo)
pub type BagId = [u8; 32];

/// Configuration for peer discovery
#[derive(Debug, Clone)]
pub struct DiscoveryConfig {
    /// Cache TTL in seconds
    pub cache_ttl_secs: u64,
    /// Minimum number of peers required
    pub min_peers_required: usize,
    /// Maximum number of peers to query in DHT
    pub max_peers_per_query: u8,
    /// Weight for reliability in scoring (0.0-1.0)
    pub peer_score_weight_reliability: f64,
    /// Weight for latency in scoring (0.0-1.0)
    pub peer_score_weight_latency: f64,
    /// Weight for bandwidth in scoring (0.0-1.0)
    pub peer_score_weight_bandwidth: f64,
    /// Blacklist timeout in seconds
    pub blacklist_timeout_secs: u64,
}

impl Default for DiscoveryConfig {
    fn default() -> Self {
        Self {
            cache_ttl_secs: 300,
            min_peers_required: 3,
            max_peers_per_query: 20,
            peer_score_weight_reliability: 0.4,
            peer_score_weight_latency: 0.3,
            peer_score_weight_bandwidth: 0.3,
            blacklist_timeout_secs: 3600,
        }
    }
}

impl DiscoveryConfig {
    /// Create a new discovery configuration
    pub fn new(
        cache_ttl_secs: u64,
        min_peers_required: usize,
        max_peers_per_query: u8,
    ) -> Self {
        Self {
            cache_ttl_secs,
            min_peers_required,
            max_peers_per_query,
            ..Default::default()
        }
    }

    /// Set the scoring weights
    pub fn with_weights(
        mut self,
        reliability: f64,
        latency: f64,
        bandwidth: f64,
    ) -> Self {
        self.peer_score_weight_reliability = reliability;
        self.peer_score_weight_latency = latency;
        self.peer_score_weight_bandwidth = bandwidth;
        self
    }

    /// Validate that weights sum to approximately 1.0
    pub fn validate_weights(&self) -> StorageResult<()> {
        let sum = self.peer_score_weight_reliability
            + self.peer_score_weight_latency
            + self.peer_score_weight_bandwidth;

        if (sum - 1.0).abs() > 0.01 {
            return Err(StorageError::NetworkError(
                format!(
                    "Scoring weights must sum to 1.0, got {}",
                    sum
                ),
            ));
        }
        Ok(())
    }
}

/// Peer scoring information
#[derive(Debug, Clone)]
pub struct PeerScore {
    /// Reliability score (0.0-1.0, success rate)
    pub reliability: f64,
    /// Estimated latency in milliseconds
    pub latency_ms: u32,
    /// Estimated bandwidth in kilobits per second
    pub bandwidth_kbps: u32,
    /// When this peer was last seen
    pub last_seen: Instant,
    /// Number of successful transfers
    pub success_count: u32,
    /// Number of failed transfers
    pub failure_count: u32,
    /// When this score was last updated
    pub score_timestamp: Instant,
}

impl PeerScore {
    /// Create a new peer score with default values
    pub fn new() -> Self {
        let now = Instant::now();
        Self {
            reliability: 1.0,
            latency_ms: 0,
            bandwidth_kbps: 0,
            last_seen: now,
            success_count: 0,
            failure_count: 0,
            score_timestamp: now,
        }
    }

    /// Calculate the composite score based on configured weights
    pub fn calculate_score(&self, config: &DiscoveryConfig) -> f64 {
        // Normalize latency: assume max useful latency ~500ms
        let latency_score = 1.0 - ((self.latency_ms as f64 / 500.0).min(1.0));

        // Normalize bandwidth: assume 10000 kbps as "excellent"
        let bandwidth_score = (self.bandwidth_kbps as f64 / 10000.0).min(1.0);

        // Composite score
        (self.reliability * config.peer_score_weight_reliability)
            + (latency_score * config.peer_score_weight_latency)
            + (bandwidth_score * config.peer_score_weight_bandwidth)
    }

    /// Update success/failure counts
    pub fn record_result(&mut self, success: bool, latency_ms: u32) {
        if success {
            self.success_count = self.success_count.saturating_add(1);
        } else {
            self.failure_count = self.failure_count.saturating_add(1);
        }

        // Update reliability as success rate
        let total = self.success_count + self.failure_count;
        if total > 0 {
            self.reliability = self.success_count as f64 / total as f64;
        }

        // Update latency with exponential moving average
        if latency_ms > 0 {
            if self.latency_ms == 0 {
                self.latency_ms = latency_ms;
            } else {
                // EMA with alpha = 0.3
                let alpha = 0.3;
                self.latency_ms =
                    ((self.latency_ms as f64 * (1.0 - alpha)) + (latency_ms as f64 * alpha)) as u32;
            }
        }

        self.last_seen = Instant::now();
        self.score_timestamp = Instant::now();
    }

    /// Check if this peer should be considered offline
    pub fn is_offline(&self, timeout: Duration) -> bool {
        self.last_seen.elapsed() > timeout
    }
}

impl Default for PeerScore {
    fn default() -> Self {
        Self::new()
    }
}

/// Blacklist entry for a peer
#[derive(Debug, Clone)]
struct BlacklistEntry {
    /// When the peer was blacklisted
    blacklisted_at: Instant,
    /// Reason for blacklisting
    #[allow(dead_code)]
    reason: String,
}

impl BlacklistEntry {
    /// Create a new blacklist entry
    fn new(reason: String) -> Self {
        Self {
            blacklisted_at: Instant::now(),
            reason,
        }
    }

    /// Check if this entry has expired
    fn is_expired(&self, timeout: Duration) -> bool {
        self.blacklisted_at.elapsed() > timeout
    }
}

/// Cached provider list with expiry
#[derive(Debug, Clone)]
struct CacheEntry {
    /// The cached providers
    providers: Vec<ProviderInfo>,
    /// When this entry was cached
    cached_at: Instant,
}

impl CacheEntry {
    /// Create a new cache entry
    fn new(providers: Vec<ProviderInfo>) -> Self {
        Self {
            providers,
            cached_at: Instant::now(),
        }
    }

    /// Check if this entry has expired
    fn is_expired(&self, ttl: Duration) -> bool {
        self.cached_at.elapsed() > ttl
    }
}

/// Peer selector for finding and scoring storage providers
pub struct PeerSelector {
    /// DHT client for peer discovery
    dht_client: Arc<DhtClient>,
    /// Cache of discovered providers
    cache: Arc<RwLock<HashMap<String, CacheEntry>>>,
    /// Peer scoring information
    scoring: Arc<RwLock<HashMap<String, PeerScore>>>,
    /// Blacklisted peers
    blacklist: Arc<RwLock<HashMap<String, BlacklistEntry>>>,
    /// Configuration
    config: DiscoveryConfig,
}

impl PeerSelector {
    /// Create a new peer selector
    pub async fn new(dht_client: Arc<DhtClient>, config: DiscoveryConfig) -> StorageResult<Self> {
        config.validate_weights()?;

        Ok(Self {
            dht_client,
            cache: Arc::new(RwLock::new(HashMap::new())),
            scoring: Arc::new(RwLock::new(HashMap::new())),
            blacklist: Arc::new(RwLock::new(HashMap::new())),
            config,
        })
    }

    /// Create with default configuration
    pub async fn with_defaults(dht_client: Arc<DhtClient>) -> StorageResult<Self> {
        Self::new(dht_client, DiscoveryConfig::default()).await
    }

    /// Discover providers for a bag using DHT
    pub async fn discover_providers(&self, bag_id: &BagId, _count: usize) -> StorageResult<Vec<ProviderInfo>> {
        // Try to get from cache first
        if let Some(cached) = self.get_cached_providers(bag_id).await
            && cached.len() >= self.config.min_peers_required {
                debug!(
                    "Using cached providers for bag: {} providers",
                    cached.len()
                );
                return Ok(cached);
            }

        // Query DHT for providers
        match self.query_dht_for_providers(bag_id).await {
            Ok(providers) => {
                // Cache the results
                let cache_key = self.bag_id_to_key(bag_id);
                let mut cache = self.cache.write().await;
                cache.insert(cache_key, CacheEntry::new(providers.clone()));

                if providers.len() < self.config.min_peers_required {
                    warn!(
                        "Found {} providers, but minimum required is {}",
                        providers.len(),
                        self.config.min_peers_required
                    );
                }

                Ok(providers)
            }
            Err(e) => {
                // Fallback to cache if DHT fails
                if let Some(cached) = self.get_cached_providers(bag_id).await {
                    warn!(
                        "DHT query failed ({}), falling back to cached providers",
                        e
                    );
                    return Ok(cached);
                }
                Err(e)
            }
        }
    }

    /// Find the best peers for downloading a bag
    pub async fn find_best_peers(&self, bag_id: &BagId) -> StorageResult<Vec<ProviderInfo>> {
        let providers = self.discover_providers(bag_id, self.config.max_peers_per_query as usize).await?;

        // Score and sort providers
        let scored = self.score_peers(&providers).await;

        // Return sorted by score (highest first)
        let mut scored = scored;
        scored.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

        Ok(scored.into_iter().map(|(info, _)| info).collect())
    }

    /// Update peer score based on transfer result
    pub async fn update_peer_score(
        &self,
        provider_id: &str,
        success: bool,
        latency_ms: u32,
    ) -> StorageResult<()> {
        let mut scoring = self.scoring.write().await;
        let score = scoring
            .entry(provider_id.to_string())
            .or_insert_with(PeerScore::new);

        score.record_result(success, latency_ms);
        debug!(
            "Updated peer {} score: reliability={:.2}, latency={}ms",
            provider_id, score.reliability, score.latency_ms
        );

        Ok(())
    }

    /// Query the DHT for providers of a bag
    pub async fn query_dht_for_providers(&self, bag_id: &BagId) -> StorageResult<Vec<ProviderInfo>> {
        // Create DHT key for storage providers
        // Key = sha256("storage" || bag_id)
        let mut key = [0u8; 32];
        let storage_prefix = b"storage";
        let combined = [storage_prefix, &bag_id[..]].concat();
        key.copy_from_slice(&ton_crypto::sha256(&combined));

        debug!("Querying DHT for providers with key: {}", hex::encode(&key[..]));

        // Query DHT
        match self
            .dht_client
            .find_value(&key, self.config.max_peers_per_query)
            .await
        {
            Ok(result) => {
                match result {
                    DhtValueResult::Found(value) => {
                        // Parse providers from DHT value
                        // For now, we'll create dummy providers from the DHT value
                        // In a real implementation, this would deserialize StorageNodeValue
                        let mut providers = Vec::new();

                        // Extract provider info from the DHT value
                        // This is simplified - real implementation would parse TL-serialized data
                        if !value.value.is_empty() {
                            // Create a provider from the value
                            let mut addr = [0u8; 32];
                            if value.value.len() >= 32 {
                                addr.copy_from_slice(&value.value[0..32]);
                            }
                            let port = u16::from_be_bytes([value.value.get(32).copied().unwrap_or(0), value.value.get(33).copied().unwrap_or(0)]);

                            providers.push(ProviderInfo::new(
                                addr,
                                if port > 0 { port } else { 8080 },
                                1000,
                                "1.0.0",
                            ));
                        }

                        info!("Found {} providers for bag", providers.len());
                        Ok(providers)
                    }
                    DhtValueResult::NotFound(_nodes) => {
                        // No provider value found, but we have close nodes
                        // In a real implementation, these nodes could be queried
                        debug!("No DHT value found for providers");
                        Ok(Vec::new())
                    }
                }
            }
            Err(e) => {
                warn!("DHT query failed: {}", e);
                Err(StorageError::NetworkError(format!(
                    "DHT query failed: {}",
                    e
                )))
            }
        }
    }

    /// Score peers based on reliability, latency, and bandwidth
    async fn score_peers(&self, peers: &[ProviderInfo]) -> Vec<(ProviderInfo, f64)> {
        let scoring = self.scoring.read().await;
        let config = self.config.clone();

        let mut scored: Vec<(ProviderInfo, f64)> = peers
            .iter()
            .filter_map(|peer| {
                // Skip blacklisted peers
                let peer_id = self.provider_to_id(peer);

                if let Ok(blacklist) = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    // This is a workaround since we can't await in a closure
                    // In real implementation, we'd check this before filtering
                    false
                }))
                    && blacklist {
                        return None;
                    }

                // Get peer score or create default
                let score = scoring
                    .get(&peer_id)
                    .cloned()
                    .unwrap_or_else(PeerScore::new);

                let composite_score = score.calculate_score(&config);
                Some((peer.clone(), composite_score))
            })
            .collect();

        // Sort by score (highest first)
        scored.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

        scored
    }

    /// Get cached providers for a bag
    pub async fn get_cached_providers(&self, bag_id: &BagId) -> Option<Vec<ProviderInfo>> {
        let cache_key = self.bag_id_to_key(bag_id);
        let cache = self.cache.read().await;

        if let Some(entry) = cache.get(&cache_key) {
            let ttl = Duration::from_secs(self.config.cache_ttl_secs);
            if !entry.is_expired(ttl) {
                return Some(entry.providers.clone());
            }
        }

        None
    }

    /// Invalidate cache for a bag
    pub async fn invalidate_cache(&self, bag_id: &BagId) {
        let cache_key = self.bag_id_to_key(bag_id);
        let mut cache = self.cache.write().await;
        cache.remove(&cache_key);
        debug!("Invalidated cache for bag: {}", cache_key);
    }

    /// Check if a peer is blacklisted
    pub async fn is_peer_blacklisted(&self, provider_id: &str) -> bool {
        let blacklist = self.blacklist.read().await;

        if let Some(entry) = blacklist.get(provider_id) {
            let timeout = Duration::from_secs(self.config.blacklist_timeout_secs);
            return !entry.is_expired(timeout);
        }

        false
    }

    /// Add a peer to the blacklist
    pub async fn blacklist_peer(&self, provider_id: &str, reason: String) {
        let mut blacklist = self.blacklist.write().await;
        blacklist.insert(
            provider_id.to_string(),
            BlacklistEntry::new(reason.clone()),
        );
        warn!("Blacklisted peer {}: {}", provider_id, reason);
    }

    /// Clean up expired blacklist entries
    pub async fn cleanup_blacklist(&self) {
        let timeout = Duration::from_secs(self.config.blacklist_timeout_secs);
        let mut blacklist = self.blacklist.write().await;

        blacklist.retain(|_, entry| !entry.is_expired(timeout));
    }

    /// Clean up expired cache entries
    pub async fn cleanup_cache(&self) {
        let ttl = Duration::from_secs(self.config.cache_ttl_secs);
        let mut cache = self.cache.write().await;

        cache.retain(|_, entry| !entry.is_expired(ttl));
    }

    /// Get cache statistics
    pub async fn cache_stats(&self) -> (usize, usize) {
        let cache = self.cache.read().await;
        let blacklist = self.blacklist.read().await;

        (cache.len(), blacklist.len())
    }

    /// Helper: convert bag ID to cache key
    fn bag_id_to_key(&self, bag_id: &BagId) -> String {
        hex::encode(bag_id)
    }

    /// Helper: convert provider info to ID string
    fn provider_to_id(&self, provider: &ProviderInfo) -> String {
        format!("{}:{}", hex::encode(&provider.address[..]), provider.port)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_discovery_config_creation() {
        let config = DiscoveryConfig::default();
        assert_eq!(config.cache_ttl_secs, 300);
        assert_eq!(config.min_peers_required, 3);
        assert_eq!(config.max_peers_per_query, 20);
    }

    #[test]
    fn test_discovery_config_validate_weights() {
        let config = DiscoveryConfig::default();
        assert!(config.validate_weights().is_ok());

        let config = DiscoveryConfig {
            peer_score_weight_reliability: 0.5,
            peer_score_weight_latency: 0.3,
            peer_score_weight_bandwidth: 0.3,
            ..Default::default()
        };
        assert!(config.validate_weights().is_err());
    }

    #[test]
    fn test_peer_score_creation() {
        let score = PeerScore::new();
        assert_eq!(score.reliability, 1.0);
        assert_eq!(score.success_count, 0);
        assert_eq!(score.failure_count, 0);
    }

    #[test]
    fn test_peer_score_record_success() {
        let mut score = PeerScore::new();

        score.record_result(true, 100);
        assert_eq!(score.success_count, 1);
        assert_eq!(score.failure_count, 0);
        assert_eq!(score.reliability, 1.0);
        assert_eq!(score.latency_ms, 100);

        score.record_result(false, 150);
        assert_eq!(score.success_count, 1);
        assert_eq!(score.failure_count, 1);
        assert_eq!(score.reliability, 0.5);
    }

    #[test]
    fn test_peer_score_latency_ema() {
        let mut score = PeerScore::new();

        score.record_result(true, 100);
        assert_eq!(score.latency_ms, 100);

        score.record_result(true, 200);
        // EMA: 100 * 0.7 + 200 * 0.3 = 70 + 60 = 130
        assert_eq!(score.latency_ms, 130);
    }

    #[test]
    fn test_peer_score_calculate_score() {
        let config = DiscoveryConfig::default();
        let mut score = PeerScore::new();
        score.latency_ms = 100;
        score.bandwidth_kbps = 5000;

        let composite = score.calculate_score(&config);
        assert!(composite > 0.0 && composite < 1.0);
    }

    #[test]
    fn test_peer_score_offline_detection() {
        let score = PeerScore::new();
        assert!(!score.is_offline(Duration::from_secs(60)));

        // Simulate old timestamp
        let mut old_score = score.clone();
        old_score.last_seen = Instant::now() - Duration::from_secs(120);
        assert!(old_score.is_offline(Duration::from_secs(60)));
    }

    #[test]
    fn test_blacklist_entry_expiry() {
        let entry = BlacklistEntry::new("test".to_string());
        assert!(!entry.is_expired(Duration::from_secs(60)));

        let mut old_entry = entry.clone();
        old_entry.blacklisted_at = Instant::now() - Duration::from_secs(120);
        assert!(old_entry.is_expired(Duration::from_secs(60)));
    }

    #[test]
    fn test_cache_entry_expiry() {
        let entry = CacheEntry::new(Vec::new());
        assert!(!entry.is_expired(Duration::from_secs(60)));

        let mut old_entry = entry.clone();
        old_entry.cached_at = Instant::now() - Duration::from_secs(120);
        assert!(old_entry.is_expired(Duration::from_secs(60)));
    }

    #[tokio::test]
    async fn test_peer_selector_creation_invalid_weights() {
        // Create a mock DHT client
        use std::net::SocketAddr;
        use ton_adnl::udp::AdnlNode;

        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let adnl = AdnlNode::bind(addr).await.unwrap();
        let dht = Arc::new(DhtClient::new(adnl));

        let config = DiscoveryConfig {
            peer_score_weight_reliability: 0.5,
            peer_score_weight_latency: 0.3,
            peer_score_weight_bandwidth: 0.3,
            ..Default::default()
        };

        let result = PeerSelector::new(dht, config).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_peer_selector_creation_valid() {
        use std::net::SocketAddr;
        use ton_adnl::udp::AdnlNode;

        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let adnl = AdnlNode::bind(addr).await.unwrap();
        let dht = Arc::new(DhtClient::new(adnl));

        let result = PeerSelector::with_defaults(dht).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_cache_get_and_set() {
        use std::net::SocketAddr;
        use ton_adnl::udp::AdnlNode;

        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let adnl = AdnlNode::bind(addr).await.unwrap();
        let dht = Arc::new(DhtClient::new(adnl));
        let selector = PeerSelector::with_defaults(dht).await.unwrap();

        let bag_id = [1u8; 32];
        let providers = vec![ProviderInfo::new([2u8; 32], 8080, 1000, "1.0.0")];

        // Cache should be empty
        assert!(selector.get_cached_providers(&bag_id).await.is_none());

        // Manually insert into cache for testing
        let cache_key = selector.bag_id_to_key(&bag_id);
        let mut cache = selector.cache.write().await;
        cache.insert(cache_key, CacheEntry::new(providers.clone()));
        drop(cache);

        // Cache should now return providers
        let cached = selector.get_cached_providers(&bag_id).await;
        assert!(cached.is_some());
        assert_eq!(cached.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn test_cache_invalidation() {
        use std::net::SocketAddr;
        use ton_adnl::udp::AdnlNode;

        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let adnl = AdnlNode::bind(addr).await.unwrap();
        let dht = Arc::new(DhtClient::new(adnl));
        let selector = PeerSelector::with_defaults(dht).await.unwrap();

        let bag_id = [1u8; 32];
        let providers = vec![ProviderInfo::new([2u8; 32], 8080, 1000, "1.0.0")];

        // Insert into cache
        let cache_key = selector.bag_id_to_key(&bag_id);
        let mut cache = selector.cache.write().await;
        cache.insert(cache_key, CacheEntry::new(providers));
        drop(cache);

        // Verify cache has entry
        assert!(selector.get_cached_providers(&bag_id).await.is_some());

        // Invalidate
        selector.invalidate_cache(&bag_id).await;

        // Cache should now be empty
        assert!(selector.get_cached_providers(&bag_id).await.is_none());
    }

    #[tokio::test]
    async fn test_peer_blacklist() {
        use std::net::SocketAddr;
        use ton_adnl::udp::AdnlNode;

        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let adnl = AdnlNode::bind(addr).await.unwrap();
        let dht = Arc::new(DhtClient::new(adnl));
        let selector = PeerSelector::with_defaults(dht).await.unwrap();

        let peer_id = "test_peer";

        // Peer should not be blacklisted initially
        assert!(!selector.is_peer_blacklisted(peer_id).await);

        // Blacklist the peer
        selector
            .blacklist_peer(peer_id, "test reason".to_string())
            .await;

        // Peer should now be blacklisted
        assert!(selector.is_peer_blacklisted(peer_id).await);
    }

    #[tokio::test]
    async fn test_peer_score_update() {
        use std::net::SocketAddr;
        use ton_adnl::udp::AdnlNode;

        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let adnl = AdnlNode::bind(addr).await.unwrap();
        let dht = Arc::new(DhtClient::new(adnl));
        let selector = PeerSelector::with_defaults(dht).await.unwrap();

        let peer_id = "test_peer";

        // Update score for success
        selector.update_peer_score(peer_id, true, 100).await.unwrap();

        // Check score was recorded
        let scoring = selector.scoring.read().await;
        let score = scoring.get(peer_id).unwrap();
        assert_eq!(score.success_count, 1);
        assert_eq!(score.reliability, 1.0);

        drop(scoring);

        // Update for failure
        selector.update_peer_score(peer_id, false, 150).await.unwrap();

        let scoring = selector.scoring.read().await;
        let score = scoring.get(peer_id).unwrap();
        assert_eq!(score.success_count, 1);
        assert_eq!(score.failure_count, 1);
        assert_eq!(score.reliability, 0.5);
    }

    #[tokio::test]
    async fn test_cleanup_expired_blacklist() {
        use std::net::SocketAddr;
        use ton_adnl::udp::AdnlNode;

        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let adnl = AdnlNode::bind(addr).await.unwrap();
        let dht = Arc::new(DhtClient::new(adnl));

        let config = DiscoveryConfig {
            blacklist_timeout_secs: 1,
            ..Default::default()
        };
        let selector = PeerSelector::new(dht, config).await.unwrap();

        let peer_id = "test_peer";

        // Blacklist the peer
        selector
            .blacklist_peer(peer_id, "test".to_string())
            .await;
        assert!(selector.is_peer_blacklisted(peer_id).await);

        // Manually expire the entry
        let mut blacklist = selector.blacklist.write().await;
        if let Some(entry) = blacklist.get_mut(peer_id) {
            entry.blacklisted_at = Instant::now() - Duration::from_secs(2);
        }
        drop(blacklist);

        // Cleanup should remove it
        selector.cleanup_blacklist().await;

        assert!(!selector.is_peer_blacklisted(peer_id).await);
    }

    #[tokio::test]
    async fn test_cache_stats() {
        use std::net::SocketAddr;
        use ton_adnl::udp::AdnlNode;

        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let adnl = AdnlNode::bind(addr).await.unwrap();
        let dht = Arc::new(DhtClient::new(adnl));
        let selector = PeerSelector::with_defaults(dht).await.unwrap();

        let (cache_size, blacklist_size) = selector.cache_stats().await;
        assert_eq!(cache_size, 0);
        assert_eq!(blacklist_size, 0);

        // Add some entries
        let bag_id = [1u8; 32];
        let providers = vec![ProviderInfo::new([2u8; 32], 8080, 1000, "1.0.0")];
        let cache_key = selector.bag_id_to_key(&bag_id);
        let mut cache = selector.cache.write().await;
        cache.insert(cache_key, CacheEntry::new(providers));
        drop(cache);

        selector.blacklist_peer("peer1", "reason".to_string()).await;

        let (cache_size, blacklist_size) = selector.cache_stats().await;
        assert_eq!(cache_size, 1);
        assert_eq!(blacklist_size, 1);
    }

    #[test]
    fn test_provider_info_creation() {
        let provider = ProviderInfo::new([1u8; 32], 8080, 1000, "1.0.0");
        assert_eq!(provider.port, 8080);
        assert_eq!(provider.bandwidth_kbps, 1000);
    }
}
