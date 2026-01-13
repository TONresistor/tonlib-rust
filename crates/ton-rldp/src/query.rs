//! RLDP Query/Answer pattern implementation.
//!
//! This module provides the query/answer pattern for RLDP, which allows
//! sending a query and receiving a response reliably over ADNL UDP.
//!
//! ## Query/Answer Protocol
//!
//! 1. Client creates an RLDP query with:
//!    - Random 256-bit query ID
//!    - Maximum expected answer size
//!    - Timeout in milliseconds
//!    - Query data
//!
//! 2. Client sends the query using RLDP transfer (FEC-encoded)
//!
//! 3. Server receives the query, processes it, and sends an answer
//!
//! 4. Client receives the answer (also FEC-encoded)
//!
//! ## Example
//!
//! ```rust,no_run
//! use ton_rldp::query::RldpQueryBuilder;
//!
//! async fn send_query() {
//!     let query_data = b"Hello, server!";
//!
//!     let query = RldpQueryBuilder::new()
//!         .data(query_data.to_vec())
//!         .max_answer_size(1024 * 1024)  // 1 MB
//!         .timeout_ms(30000)             // 30 seconds
//!         .build();
//!
//!     // Send via RLDP transfer...
//! }
//! ```

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use rand::RngCore;
use tokio::sync::{oneshot, Mutex};
use tokio::time::timeout;

use crate::error::{RldpError, Result};
use crate::types::{RldpAnswer, RldpQuery};

/// Default maximum answer size (2 MB).
pub const DEFAULT_MAX_ANSWER_SIZE: i64 = 2 * 1024 * 1024;

/// Default query timeout (30 seconds).
pub const DEFAULT_QUERY_TIMEOUT_MS: i32 = 30000;

/// Generates a random query ID.
pub fn generate_query_id() -> [u8; 32] {
    let mut id = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut id);
    id
}

/// Derives the expected answer transfer ID from a query ID using XOR pattern.
///
/// Official TON RLDP uses XOR with all 0xFF to correlate query and answer transfers:
/// `response_transfer_id = query_id XOR 0xFFFFFFFF...`
///
/// This enables bidirectional correlation without additional state tracking.
pub fn derive_answer_transfer_id(query_id: &[u8; 32]) -> [u8; 32] {
    let mut answer_id = [0u8; 32];
    for i in 0..32 {
        answer_id[i] = query_id[i] ^ 0xFF;
    }
    answer_id
}

/// Builder for RLDP queries.
#[derive(Debug, Clone)]
pub struct RldpQueryBuilder {
    query_id: Option<[u8; 32]>,
    max_answer_size: i64,
    timeout_ms: i32,
    data: Vec<u8>,
}

impl Default for RldpQueryBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl RldpQueryBuilder {
    /// Creates a new query builder with default values.
    pub fn new() -> Self {
        Self {
            query_id: None,
            max_answer_size: DEFAULT_MAX_ANSWER_SIZE,
            timeout_ms: DEFAULT_QUERY_TIMEOUT_MS,
            data: Vec::new(),
        }
    }

    /// Sets the query ID (optional, generates random if not set).
    pub fn query_id(mut self, id: [u8; 32]) -> Self {
        self.query_id = Some(id);
        self
    }

    /// Sets the maximum expected answer size.
    pub fn max_answer_size(mut self, size: i64) -> Self {
        self.max_answer_size = size;
        self
    }

    /// Sets the timeout in milliseconds.
    pub fn timeout_ms(mut self, ms: i32) -> Self {
        self.timeout_ms = ms;
        self
    }

    /// Sets the timeout as a Duration.
    pub fn timeout(mut self, duration: Duration) -> Self {
        self.timeout_ms = duration.as_millis() as i32;
        self
    }

    /// Sets the query data.
    pub fn data(mut self, data: Vec<u8>) -> Self {
        self.data = data;
        self
    }

    /// Builds the RLDP query.
    pub fn build(self) -> RldpQuery {
        let query_id = self.query_id.unwrap_or_else(generate_query_id);
        RldpQuery::new(query_id, self.max_answer_size, self.timeout_ms, self.data)
    }
}

/// State of a pending query.
#[derive(Debug)]
pub struct PendingQuery {
    /// The query that was sent.
    pub query: RldpQuery,
    /// When the query was started.
    pub start_time: Instant,
    /// Transfer ID for the query.
    pub transfer_id: [u8; 32],
    /// Channel to send the answer back.
    answer_tx: Option<oneshot::Sender<Result<Vec<u8>>>>,
}

impl PendingQuery {
    /// Creates a new pending query.
    pub fn new(query: RldpQuery) -> (Self, oneshot::Receiver<Result<Vec<u8>>>) {
        let (tx, rx) = oneshot::channel();
        let pending = Self {
            query,
            start_time: Instant::now(),
            transfer_id: [0u8; 32], // Will be set when transfer starts
            answer_tx: Some(tx),
        };
        (pending, rx)
    }

    /// Sets the transfer ID.
    pub fn set_transfer_id(&mut self, id: [u8; 32]) {
        self.transfer_id = id;
    }

    /// Returns the timeout duration.
    pub fn timeout(&self) -> Duration {
        Duration::from_millis(self.query.timeout as u64)
    }

    /// Returns whether the query has timed out.
    pub fn is_timed_out(&self) -> bool {
        self.start_time.elapsed() > self.timeout()
    }

    /// Returns the time remaining until timeout.
    pub fn time_remaining(&self) -> Duration {
        self.timeout().saturating_sub(self.start_time.elapsed())
    }

    /// Completes the query with an answer.
    pub fn complete(mut self, data: Vec<u8>) {
        if let Some(tx) = self.answer_tx.take() {
            let _ = tx.send(Ok(data));
        }
    }

    /// Fails the query with an error.
    pub fn fail(mut self, error: RldpError) {
        if let Some(tx) = self.answer_tx.take() {
            let _ = tx.send(Err(error));
        }
    }
}

/// Manager for RLDP queries and answers.
#[derive(Debug)]
pub struct QueryManager {
    /// Pending queries by query ID.
    pending: HashMap<[u8; 32], PendingQuery>,
    /// Mapping from transfer ID to query ID.
    transfer_to_query: HashMap<[u8; 32], [u8; 32]>,
    /// Received answers waiting to be processed.
    answers: HashMap<[u8; 32], RldpAnswer>,
}

impl Default for QueryManager {
    fn default() -> Self {
        Self::new()
    }
}

impl QueryManager {
    /// Creates a new query manager.
    pub fn new() -> Self {
        Self {
            pending: HashMap::new(),
            transfer_to_query: HashMap::new(),
            answers: HashMap::new(),
        }
    }

    /// Registers a new pending query.
    ///
    /// Returns a receiver that will receive the answer.
    pub fn register_query(&mut self, query: RldpQuery) -> oneshot::Receiver<Result<Vec<u8>>> {
        let query_id = query.query_id;
        let (pending, rx) = PendingQuery::new(query);
        self.pending.insert(query_id, pending);
        rx
    }

    /// Associates a transfer ID with a query.
    pub fn set_transfer_id(&mut self, query_id: &[u8; 32], transfer_id: [u8; 32]) {
        if let Some(pending) = self.pending.get_mut(query_id) {
            pending.set_transfer_id(transfer_id);
            self.transfer_to_query.insert(transfer_id, *query_id);
        }
    }

    /// Handles a received answer.
    ///
    /// Returns `true` if the answer was matched to a pending query.
    pub fn handle_answer(&mut self, answer: RldpAnswer) -> bool {
        let query_id = answer.query_id;

        if let Some(pending) = self.pending.remove(&query_id) {
            // Remove transfer mapping
            self.transfer_to_query.remove(&pending.transfer_id);

            // Complete the query
            pending.complete(answer.data);
            true
        } else {
            // Store for later (might arrive before query is fully registered)
            self.answers.insert(query_id, answer);
            false
        }
    }

    /// Gets a pending query by its query ID.
    pub fn get_pending(&self, query_id: &[u8; 32]) -> Option<&PendingQuery> {
        self.pending.get(query_id)
    }

    /// Gets a pending query by its transfer ID.
    pub fn get_pending_by_transfer(&self, transfer_id: &[u8; 32]) -> Option<&PendingQuery> {
        let query_id = self.transfer_to_query.get(transfer_id)?;
        self.pending.get(query_id)
    }

    /// Cleans up timed-out queries.
    pub fn cleanup_timed_out(&mut self) {
        let timed_out: Vec<_> = self
            .pending
            .iter()
            .filter(|(_, q)| q.is_timed_out())
            .map(|(id, _)| *id)
            .collect();

        for query_id in timed_out {
            if let Some(pending) = self.pending.remove(&query_id) {
                self.transfer_to_query.remove(&pending.transfer_id);
                pending.fail(RldpError::Timeout);
            }
        }

        // Also clean up old answers
        let old_answers: Vec<_> = self
            .answers
            .keys()
            .cloned()
            .collect();

        // Keep answers for at most 60 seconds
        // (In a real implementation, we'd track answer age)
        if self.answers.len() > 100 {
            for key in old_answers.into_iter().take(50) {
                self.answers.remove(&key);
            }
        }
    }

    /// Returns the number of pending queries.
    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }

    /// Cancels a pending query.
    pub fn cancel(&mut self, query_id: &[u8; 32]) {
        if let Some(pending) = self.pending.remove(query_id) {
            self.transfer_to_query.remove(&pending.transfer_id);
            pending.fail(RldpError::Cancelled);
        }
    }
}

/// A thread-safe query manager.
pub type SharedQueryManager = Arc<Mutex<QueryManager>>;

/// Creates a new shared query manager.
pub fn new_shared_manager() -> SharedQueryManager {
    Arc::new(Mutex::new(QueryManager::new()))
}

/// Creates an RLDP query for sending.
///
/// This is a convenience function that:
/// 1. Creates the query
/// 2. Serializes it
/// 3. Returns the query ID and serialized data
pub fn create_query(data: &[u8], max_answer_size: i64, timeout_ms: i32) -> (RldpQuery, Vec<u8>) {
    let query = RldpQueryBuilder::new()
        .data(data.to_vec())
        .max_answer_size(max_answer_size)
        .timeout_ms(timeout_ms)
        .build();

    let bytes = query.to_bytes();
    (query, bytes)
}

/// Creates an RLDP answer for a query.
pub fn create_answer(query_id: [u8; 32], data: Vec<u8>) -> (RldpAnswer, Vec<u8>) {
    let answer = RldpAnswer::new(query_id, data);
    let bytes = answer.to_bytes();
    (answer, bytes)
}

/// Parses an incoming RLDP query from raw data.
pub fn parse_query(data: &[u8]) -> Result<RldpQuery> {
    use ton_adnl::TlReader;
    use crate::types::RLDP_QUERY;

    let mut reader = TlReader::new(data);
    let schema_id = reader.peek_u32().map_err(|e| RldpError::ParseError(e.to_string()))?;

    if schema_id != RLDP_QUERY {
        return Err(RldpError::ParseError(format!(
            "Expected RLDP query (0x{:08x}), got 0x{:08x}",
            RLDP_QUERY, schema_id
        )));
    }

    RldpQuery::read_from(&mut reader).map_err(|e| RldpError::ParseError(e.to_string()))
}

/// Parses an incoming RLDP answer from raw data.
pub fn parse_answer(data: &[u8]) -> Result<RldpAnswer> {
    use ton_adnl::TlReader;
    use crate::types::RLDP_ANSWER;

    let mut reader = TlReader::new(data);
    let schema_id = reader.peek_u32().map_err(|e| RldpError::ParseError(e.to_string()))?;

    if schema_id != RLDP_ANSWER {
        return Err(RldpError::ParseError(format!(
            "Expected RLDP answer (0x{:08x}), got 0x{:08x}",
            RLDP_ANSWER, schema_id
        )));
    }

    RldpAnswer::read_from(&mut reader).map_err(|e| RldpError::ParseError(e.to_string()))
}

/// High-level RLDP query function.
///
/// This function handles the complete query/answer cycle:
/// 1. Creates and sends the query via RLDP transfer
/// 2. Waits for the answer
/// 3. Returns the answer data
///
/// The `send_fn` parameter is a function that sends RLDP message parts
/// and receives incoming parts. This allows integration with any transport.
pub async fn rldp_query<F, Fut>(
    query_data: &[u8],
    max_answer_size: i64,
    timeout_ms: i32,
    send_fn: F,
) -> Result<Vec<u8>>
where
    F: FnOnce(Vec<u8>) -> Fut,
    Fut: std::future::Future<Output = Result<Vec<u8>>>,
{
    // Create the query
    let (query, query_bytes) = create_query(query_data, max_answer_size, timeout_ms);

    // Set up timeout
    let timeout_duration = Duration::from_millis(timeout_ms as u64);

    // Send query and wait for answer
    let answer_bytes = timeout(timeout_duration, send_fn(query_bytes))
        .await
        .map_err(|_| RldpError::Timeout)??;

    // Parse answer
    let answer = parse_answer(&answer_bytes)?;

    // Verify query ID matches
    if answer.query_id != query.query_id {
        return Err(RldpError::QueryIdMismatch);
    }

    Ok(answer.data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_query_id() {
        let id1 = generate_query_id();
        let id2 = generate_query_id();

        assert_ne!(id1, id2);
        assert_eq!(id1.len(), 32);
    }

    #[test]
    fn test_derive_answer_transfer_id_xor() {
        let query_id = [0x12u8; 32];
        let answer_id = derive_answer_transfer_id(&query_id);

        // XOR with 0xFF should give 0xED (0x12 ^ 0xFF = 0xED)
        assert_eq!(answer_id[0], 0x12 ^ 0xFF);
        assert_eq!(answer_id[31], 0x12 ^ 0xFF);

        // XOR is involutive: applying twice gives original
        let original = derive_answer_transfer_id(&answer_id);
        assert_eq!(original, query_id);
    }

    #[test]
    fn test_derive_answer_transfer_id_roundtrip() {
        let query_id = generate_query_id();
        let answer_id = derive_answer_transfer_id(&query_id);

        // Double XOR should return original
        let recovered = derive_answer_transfer_id(&answer_id);
        assert_eq!(recovered, query_id);

        // They should be different
        assert_ne!(query_id, answer_id);
    }

    #[test]
    fn test_query_builder_defaults() {
        let query = RldpQueryBuilder::new()
            .data(b"test".to_vec())
            .build();

        assert_eq!(query.max_answer_size, DEFAULT_MAX_ANSWER_SIZE);
        assert_eq!(query.timeout, DEFAULT_QUERY_TIMEOUT_MS);
        assert_eq!(query.data, b"test");
    }

    #[test]
    fn test_query_builder_custom() {
        let query_id = [42u8; 32];
        let query = RldpQueryBuilder::new()
            .query_id(query_id)
            .max_answer_size(1024)
            .timeout_ms(5000)
            .data(b"hello".to_vec())
            .build();

        assert_eq!(query.query_id, query_id);
        assert_eq!(query.max_answer_size, 1024);
        assert_eq!(query.timeout, 5000);
        assert_eq!(query.data, b"hello");
    }

    #[test]
    fn test_query_builder_timeout_duration() {
        let query = RldpQueryBuilder::new()
            .timeout(Duration::from_secs(10))
            .data(vec![])
            .build();

        assert_eq!(query.timeout, 10000);
    }

    #[test]
    fn test_pending_query() {
        let query = RldpQueryBuilder::new()
            .timeout_ms(1000)
            .data(b"test".to_vec())
            .build();

        let (pending, _rx) = PendingQuery::new(query);

        assert!(!pending.is_timed_out());
        assert!(pending.time_remaining() <= Duration::from_millis(1000));
    }

    #[test]
    fn test_query_manager_register() {
        let mut manager = QueryManager::new();

        let query = RldpQueryBuilder::new()
            .data(b"test".to_vec())
            .build();
        let query_id = query.query_id;

        let _rx = manager.register_query(query);

        assert_eq!(manager.pending_count(), 1);
        assert!(manager.get_pending(&query_id).is_some());
    }

    #[test]
    fn test_query_manager_answer() {
        let mut manager = QueryManager::new();

        let query = RldpQueryBuilder::new()
            .data(b"test query".to_vec())
            .build();
        let query_id = query.query_id;

        let _rx = manager.register_query(query);

        // Create answer
        let answer = RldpAnswer::new(query_id, b"test answer".to_vec());

        // Handle answer
        let matched = manager.handle_answer(answer);
        assert!(matched);
        assert_eq!(manager.pending_count(), 0);

        // Check that answer was received
        // (In a real test, we'd poll the receiver)
    }

    #[test]
    fn test_query_manager_transfer_mapping() {
        let mut manager = QueryManager::new();

        let query = RldpQueryBuilder::new()
            .data(b"test".to_vec())
            .build();
        let query_id = query.query_id;
        let transfer_id = [1u8; 32];

        let _rx = manager.register_query(query);
        manager.set_transfer_id(&query_id, transfer_id);

        let pending = manager.get_pending_by_transfer(&transfer_id);
        assert!(pending.is_some());
        assert_eq!(pending.unwrap().query.query_id, query_id);
    }

    #[test]
    fn test_query_manager_cancel() {
        let mut manager = QueryManager::new();

        let query = RldpQueryBuilder::new()
            .data(b"test".to_vec())
            .build();
        let query_id = query.query_id;

        let _rx = manager.register_query(query);
        assert_eq!(manager.pending_count(), 1);

        manager.cancel(&query_id);
        assert_eq!(manager.pending_count(), 0);
    }

    #[test]
    fn test_create_query() {
        let (query, bytes) = create_query(b"test data", 1024 * 1024, 30000);

        assert_eq!(query.data, b"test data");
        assert_eq!(query.max_answer_size, 1024 * 1024);
        assert_eq!(query.timeout, 30000);
        assert!(!bytes.is_empty());
    }

    #[test]
    fn test_create_answer() {
        let query_id = [42u8; 32];
        let (answer, bytes) = create_answer(query_id, b"response data".to_vec());

        assert_eq!(answer.query_id, query_id);
        assert_eq!(answer.data, b"response data");
        assert!(!bytes.is_empty());
    }

    #[test]
    fn test_parse_query() {
        let (original, bytes) = create_query(b"test", 1024, 5000);

        let parsed = parse_query(&bytes).unwrap();
        assert_eq!(parsed.query_id, original.query_id);
        assert_eq!(parsed.data, original.data);
        assert_eq!(parsed.max_answer_size, original.max_answer_size);
        assert_eq!(parsed.timeout, original.timeout);
    }

    #[test]
    fn test_parse_answer() {
        let query_id = [42u8; 32];
        let (original, bytes) = create_answer(query_id, b"answer".to_vec());

        let parsed = parse_answer(&bytes).unwrap();
        assert_eq!(parsed.query_id, original.query_id);
        assert_eq!(parsed.data, original.data);
    }

    #[test]
    fn test_parse_query_wrong_type() {
        // Create an answer and try to parse as query
        let (_, bytes) = create_answer([0u8; 32], vec![]);

        let result = parse_query(&bytes);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_answer_wrong_type() {
        // Create a query and try to parse as answer
        let (_, bytes) = create_query(b"test", 1024, 5000);

        let result = parse_answer(&bytes);
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_rldp_query_timeout() {
        let result = rldp_query(
            b"test",
            1024,
            100, // 100ms timeout
            |_| async {
                // Simulate slow response
                tokio::time::sleep(Duration::from_millis(200)).await;
                Ok(vec![])
            },
        )
        .await;

        assert!(matches!(result, Err(RldpError::Timeout)));
    }

    #[tokio::test]
    async fn test_rldp_query_success() {
        let query_id = std::sync::Arc::new(std::sync::Mutex::new([0u8; 32]));
        let query_id_clone = query_id.clone();

        let result = rldp_query(
            b"test query",
            1024 * 1024,
            5000,
            move |query_bytes| async move {
                // Parse the query to get its ID
                let query = parse_query(&query_bytes)?;
                *query_id_clone.lock().unwrap() = query.query_id;

                // Create a matching answer
                let (_, answer_bytes) = create_answer(query.query_id, b"test response".to_vec());
                Ok(answer_bytes)
            },
        )
        .await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), b"test response");
    }
}
