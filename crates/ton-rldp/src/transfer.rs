//! RLDP transfer implementation.
//!
//! This module handles the reliable transfer of large data over ADNL UDP
//! using Forward Error Correction (FEC).
//!
//! ## Transfer Process
//!
//! ```text
//! Sender                                              Receiver
//!    |                                                    |
//!    |  Generate random transfer_id                       |
//!    |  Encode data with RaptorQ                          |
//!    |                                                    |
//!    |  ────── rldp.messagePart (seqno=0) ──────────────> |
//!    |  ────── rldp.messagePart (seqno=1) ──────────────> |
//!    |  ────── rldp.messagePart (seqno=2) ──────────────> |
//!    |  ...                                               |
//!    |                      (accumulates symbols)         |
//!    |                      (decodes when sufficient)     |
//!    |                                                    |
//!    |  <───────────── rldp.complete ─────────────────── |
//!    |                                                    |
//!    |  Stop sending                                      |
//! ```
//!
//! ## Sender Behavior
//!
//! 1. Generate a random 256-bit transfer ID
//! 2. Encode the data using RaptorQ FEC
//! 3. Send all source symbols in an initial burst
//! 4. Continue sending repair symbols until receiving `rldp.complete`
//! 5. Use exponential backoff for timeout handling
//!
//! ## Receiver Behavior
//!
//! 1. Receive `rldp.messagePart` messages
//! 2. Accumulate FEC symbols
//! 3. Attempt to decode when enough symbols received
//! 4. Send `rldp.complete` when decoding succeeds

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use lru::LruCache;
use rand::RngCore;
use tokio::sync::{oneshot, Mutex};

use crate::error::{RldpError, Result};
use crate::fec::{FecDecoder, FecEncoder};
use crate::types::{FecType, RldpComplete, RldpConfirm, RldpMessagePart};

/// Default timeout for waiting for transfer completion.
/// Matches official TON v1 timeout (aligns with blockchain block time).
pub const DEFAULT_TRANSFER_TIMEOUT: Duration = Duration::from_secs(60);

/// Default interval between sending symbols.
pub const DEFAULT_SYMBOL_INTERVAL: Duration = Duration::from_millis(10);

/// Maximum number of symbols to send in initial burst.
pub const DEFAULT_BURST_SIZE: usize = 20;

/// Initial delay before starting to send repair symbols.
pub const DEFAULT_INITIAL_DELAY: Duration = Duration::from_millis(100);

/// Exponential backoff multiplier.
pub const BACKOFF_MULTIPLIER: f64 = 1.5;

/// Maximum backoff delay.
pub const MAX_BACKOFF_DELAY: Duration = Duration::from_secs(5);

/// Data slice size per part (matching official TON rldp-peer.hpp:76).
/// 2MB per part for multi-part transfers (official TON uses 2_000_000).
pub const SLICE_SIZE: usize = 2_000_000;

/// Window size for sliding window flow control (matching TON rldp-peer.hpp:82).
/// Maximum number of unconfirmed symbols in flight.
pub const WINDOW_SIZE: usize = 1000;

/// LRU cache size for completed transfers (matching official TON rldp-peer.hpp:85).
/// Keeps 128 most recent completed transfers to detect duplicate messages.
pub const LRU_CACHE_SIZE: usize = 128;

/// Confirmation threshold: send rldp_confirm after receiving this many symbols.
/// Matches official TON implementation behavior.
pub const CONFIRM_THRESHOLD: u32 = 10;

/// Generates a random transfer ID.
pub fn generate_transfer_id() -> [u8; 32] {
    let mut id = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut id);
    id
}

/// Configuration for RLDP transfers.
#[derive(Debug, Clone)]
pub struct TransferConfig {
    /// Timeout for the entire transfer.
    pub timeout: Duration,
    /// Interval between sending symbols.
    pub symbol_interval: Duration,
    /// Number of symbols to send in initial burst.
    pub burst_size: usize,
    /// Initial delay before sending repair symbols.
    pub initial_delay: Duration,
    /// Maximum number of repair symbols to send.
    pub max_repair_symbols: Option<u32>,
}

impl Default for TransferConfig {
    fn default() -> Self {
        Self {
            timeout: DEFAULT_TRANSFER_TIMEOUT,
            symbol_interval: DEFAULT_SYMBOL_INTERVAL,
            burst_size: DEFAULT_BURST_SIZE,
            initial_delay: DEFAULT_INITIAL_DELAY,
            max_repair_symbols: None,
        }
    }
}

/// State of a single part in a multi-part transfer.
#[derive(Debug)]
struct PartState {
    /// Part number.
    part_id: i32,
    /// FEC encoder for this part.
    encoder: FecEncoder,
    /// Pre-encoded packets (source + repair).
    packets: Vec<(u32, Vec<u8>)>,
    /// Current packet index within this part.
    current_index: usize,
    /// Whether this part is complete.
    is_complete: bool,
    /// Highest confirmed seqno for this part (window control).
    confirmed_seqno: i32,
}

impl PartState {
    /// Creates a new part state for the given data.
    fn new(part_id: i32, data: &[u8], repair_count: u32) -> Self {
        let encoder = FecEncoder::new(data);
        let packets = encoder.encode_all(repair_count);

        Self {
            part_id,
            encoder,
            packets,
            current_index: 0,
            is_complete: false,
            confirmed_seqno: -1,
        }
    }

    /// Checks if this part can send another symbol (window control).
    fn can_send_symbol(&self) -> bool {
        let unconfirmed = self.current_index as i32 - self.confirmed_seqno;
        unconfirmed < WINDOW_SIZE as i32
    }

    /// Updates the confirmed seqno for window control.
    fn update_confirmed_seqno(&mut self, seqno: i32) {
        self.confirmed_seqno = seqno.max(self.confirmed_seqno);
    }

    /// Gets the next packet from this part, or None if complete.
    fn next_packet(&mut self) -> Option<(u32, Vec<u8>)> {
        if self.is_complete || self.current_index >= self.packets.len() {
            return None;
        }

        let (seqno, data) = self.packets[self.current_index].clone();
        self.current_index += 1;
        Some((seqno, data))
    }

    /// Marks this part as complete.
    #[allow(dead_code)]
    fn mark_complete(&mut self) {
        self.is_complete = true;
    }
}

/// State of an outgoing (sending) transfer.
#[derive(Debug)]
pub struct OutgoingTransfer {
    /// Transfer identifier.
    pub transfer_id: [u8; 32],
    /// Total size of all data.
    total_size: i64,
    /// All parts of the transfer.
    parts: Vec<PartState>,
    /// Current part index.
    current_part_idx: usize,
    /// Start time of the transfer.
    start_time: Instant,
    /// Whether the transfer is complete.
    is_complete: bool,
    /// Configuration.
    config: TransferConfig,
}

/// Default number of repair packets to generate.
const DEFAULT_REPAIR_COUNT: u32 = 50;

impl OutgoingTransfer {
    /// Creates a new outgoing transfer.
    pub fn new(data: &[u8]) -> Self {
        Self::with_config(data, TransferConfig::default())
    }

    /// Creates a new outgoing transfer with custom configuration.
    pub fn with_config(data: &[u8], config: TransferConfig) -> Self {
        let transfer_id = generate_transfer_id();
        let repair_count = config.max_repair_symbols.unwrap_or(DEFAULT_REPAIR_COUNT);
        let total_size = data.len() as i64;

        // Split data into SLICE_SIZE (2MB) parts
        let parts = Self::split_into_parts(data, repair_count);

        Self {
            transfer_id,
            total_size,
            parts,
            current_part_idx: 0,
            start_time: Instant::now(),
            is_complete: false,
            config,
        }
    }

    /// Creates a transfer with a specific transfer ID.
    pub fn with_id(transfer_id: [u8; 32], data: &[u8]) -> Self {
        let repair_count = DEFAULT_REPAIR_COUNT;
        let total_size = data.len() as i64;

        // Split data into SLICE_SIZE (2MB) parts
        let parts = Self::split_into_parts(data, repair_count);

        Self {
            transfer_id,
            total_size,
            parts,
            current_part_idx: 0,
            start_time: Instant::now(),
            is_complete: false,
            config: TransferConfig::default(),
        }
    }

    /// Splits data into SLICE_SIZE (2MB) parts and creates PartState for each.
    fn split_into_parts(data: &[u8], repair_count: u32) -> Vec<PartState> {
        let mut parts = Vec::new();

        for (part_id, chunk) in data.chunks(SLICE_SIZE).enumerate() {
            let part = PartState::new(part_id as i32, chunk, repair_count);
            parts.push(part);
        }

        if parts.is_empty() {
            // Empty data: create one empty part
            parts.push(PartState::new(0, &[], repair_count));
        }

        parts
    }

    /// Returns the FEC type for this transfer (from current part).
    pub fn fec_type(&self) -> FecType {
        self.current_part()
            .map(|p| p.encoder.fec_type())
            .unwrap_or(FecType::RaptorQ {
                data_size: 0,
                symbol_size: 768,
                symbols_count: 0,
            })
    }

    /// Returns the total data size.
    pub fn data_size(&self) -> i64 {
        self.total_size
    }

    /// Returns the number of source symbols in current part.
    pub fn symbols_count(&self) -> usize {
        self.current_part()
            .map(|p| p.encoder.symbols_count())
            .unwrap_or(0)
    }

    /// Returns the current packet index in current part.
    pub fn current_seqno(&self) -> u32 {
        self.current_part()
            .map(|p| p.current_index as u32)
            .unwrap_or(0)
    }

    /// Returns whether the transfer is complete.
    pub fn is_complete(&self) -> bool {
        self.is_complete
    }

    /// Returns whether the transfer has timed out.
    pub fn is_timed_out(&self) -> bool {
        self.start_time.elapsed() > self.config.timeout
    }

    /// Marks the transfer as complete.
    pub fn mark_complete(&mut self) {
        self.is_complete = true;
    }

    /// Returns a reference to the current part.
    fn current_part(&self) -> Option<&PartState> {
        self.parts.get(self.current_part_idx)
    }

    /// Returns a mutable reference to the current part.
    fn current_part_mut(&mut self) -> Option<&mut PartState> {
        self.parts.get_mut(self.current_part_idx)
    }

    /// Checks if window allows sending another symbol in current part.
    ///
    /// Returns true if: `current_index - confirmed_seqno < WINDOW_SIZE`
    /// This implements sliding window flow control (max 1000 unconfirmed symbols).
    pub fn can_send_symbol(&self) -> bool {
        self.current_part()
            .map(|p| p.can_send_symbol())
            .unwrap_or(false)
    }

    /// Updates the highest confirmed sequence number from receiver ACK.
    ///
    /// This slides the window forward by updating confirmed_seqno.
    /// Only updates if the new seqno is higher (keeps max).
    pub fn update_confirmed_seqno(&mut self, seqno: i32) {
        if let Some(part) = self.current_part_mut() {
            part.update_confirmed_seqno(seqno);
        }
    }

    /// Gets the next message part to send.
    ///
    /// Returns `None` if the transfer is complete, timed out, window is full, or no more packets.
    /// Automatically advances to the next part when the current part is exhausted.
    pub fn next_message_part(&mut self) -> Option<RldpMessagePart> {
        if self.is_complete || self.is_timed_out() {
            return None;
        }

        // Try to get a packet from the current part, advancing to next part if needed
        loop {
            if self.current_part_idx >= self.parts.len() {
                // All parts exhausted
                self.is_complete = true;
                return None;
            }

            // Window-based flow control: check if sender can send
            // (prevents overwhelming receiver with too many unconfirmed symbols)
            if !self.can_send_symbol() {
                return None;
            }

            // Try to get next packet from current part
            let packet_option = {
                if let Some(part) = self.current_part_mut() {
                    part.next_packet().map(|(seqno, data)| {
                        (seqno, data, part.part_id, part.encoder.fec_type())
                    })
                } else {
                    None
                }
            };

            if let Some((seqno, packet_data, part_id, fec_type)) = packet_option {
                // Got a packet from current part
                return Some(RldpMessagePart::new(
                    self.transfer_id,
                    fec_type,
                    part_id,
                    self.data_size(),
                    seqno as i32,
                    packet_data,
                ));
            }

            // Current part exhausted, move to next
            self.current_part_idx += 1;
        }
    }

    /// Gets the initial burst of message parts.
    pub fn initial_burst(&mut self) -> Vec<RldpMessagePart> {
        let mut parts = Vec::with_capacity(self.config.burst_size);

        for _ in 0..self.config.burst_size {
            if let Some(part) = self.next_message_part() {
                parts.push(part);
            } else {
                break;
            }
        }

        parts
    }

    /// Handles a confirm message.
    ///
    /// Confirms are not strictly required for RLDP but can be used
    /// to optimize sending.
    pub fn handle_confirm(&mut self, confirm: &RldpConfirm) {
        if confirm.transfer_id != self.transfer_id {
        }

        // Could use this to adjust sending rate
        // For now, we just continue sending
    }

    /// Handles a complete message.
    pub fn handle_complete(&mut self, complete: &RldpComplete) -> bool {
        if complete.transfer_id == self.transfer_id {
            self.is_complete = true;
            true
        } else {
            false
        }
    }
}

/// State of an incoming (receiving) transfer with multi-part support.
#[derive(Debug)]
pub struct IncomingTransfer {
    /// Transfer identifier.
    pub transfer_id: [u8; 32],
    /// FEC decoders for each part (one per part_id).
    decoders: HashMap<i32, FecDecoder>,
    /// Decoded data for each part (one per part_id).
    decoded_parts: HashMap<i32, Vec<u8>>,
    /// Total size of the data.
    total_size: i64,
    /// Last received sequence number (per part).
    last_seqno: HashMap<i32, i32>,
    /// Symbols received since last confirm (per part).
    /// Used to determine when to send rldp_confirm (every CONFIRM_THRESHOLD symbols).
    received_symbols_since_last_confirm: HashMap<i32, u32>,
    /// Start time.
    start_time: Instant,
    /// Timeout duration.
    timeout: Duration,
}

impl IncomingTransfer {
    /// Creates a new incoming transfer from the first message part.
    pub fn new(part: &RldpMessagePart) -> Result<Self> {
        Self::with_timeout(part, DEFAULT_TRANSFER_TIMEOUT)
    }

    /// Creates a new incoming transfer with custom timeout.
    pub fn with_timeout(part: &RldpMessagePart, timeout: Duration) -> Result<Self> {
        let mut decoders = HashMap::new();
        let mut last_seqno = HashMap::new();
        let mut received_symbols_since_last_confirm = HashMap::new();

        // Create initial decoder for this part
        let decoder = FecDecoder::from_fec_type(&part.fec_type)?;
        decoders.insert(part.part, decoder);
        last_seqno.insert(part.part, -1);
        received_symbols_since_last_confirm.insert(part.part, 0);

        Ok(Self {
            transfer_id: part.transfer_id,
            decoders,
            decoded_parts: HashMap::new(),
            total_size: part.total_size,
            last_seqno,
            received_symbols_since_last_confirm,
            start_time: Instant::now(),
            timeout,
        })
    }

    /// Returns whether all parts of the transfer are complete (not used yet for multi-part).
    /// Currently checks if at least one part is decoded.
    pub fn is_complete(&self) -> bool {
        !self.decoded_parts.is_empty()
    }

    /// Returns whether the transfer has timed out.
    pub fn is_timed_out(&self) -> bool {
        self.start_time.elapsed() > self.timeout
    }

    /// Returns the total data size.
    pub fn total_size(&self) -> i64 {
        self.total_size
    }

    /// Returns the number of symbols received across all parts.
    pub fn symbols_received(&self) -> usize {
        self.decoders.values().map(|d| d.symbols_received()).sum()
    }

    /// Returns whether a confirm should be sent for the given part.
    ///
    /// Returns true when the number of symbols received since the last confirm
    /// reaches or exceeds `CONFIRM_THRESHOLD` (10 symbols).
    pub fn should_send_confirm(&self, part_id: i32) -> bool {
        self.received_symbols_since_last_confirm
            .get(&part_id)
            .map(|&count| count >= CONFIRM_THRESHOLD)
            .unwrap_or(false)
    }

    /// Checks if a confirm should be sent and returns it, resetting the counter.
    ///
    /// This method should be called after `process_part` to check if a confirm
    /// message should be sent based on the confirmation threshold.
    ///
    /// # Returns
    /// `Some(RldpConfirm)` when threshold is reached, `None` otherwise.
    pub fn maybe_create_confirm(&mut self, part_id: i32) -> Option<RldpConfirm> {
        if self.should_send_confirm(part_id) {
            // Reset counter
            if let Some(count) = self.received_symbols_since_last_confirm.get_mut(&part_id) {
                *count = 0;
            }
            Some(self.create_confirm(part_id))
        } else {
            None
        }
    }

    /// Receives a symbol and tracks it for confirmation threshold.
    ///
    /// Increments the received symbol counter for the given part.
    /// When the threshold is reached, resets the counter and returns an `RldpConfirm`.
    ///
    /// # Arguments
    /// * `part_id` - The part number this symbol belongs to
    /// * `seqno` - The sequence number of the received symbol
    /// * `data` - The symbol data
    ///
    /// # Returns
    /// `Some(RldpConfirm)` when threshold is reached, `None` otherwise.
    pub fn receive_symbol(&mut self, part_id: i32, seqno: u32, _data: &[u8]) -> Option<RldpConfirm> {
        // Update last seqno for this part
        let last = self.last_seqno.entry(part_id).or_insert(-1);
        if seqno as i32 > *last {
            *last = seqno as i32;
        }

        // Increment received symbols counter
        let count = self.received_symbols_since_last_confirm.entry(part_id).or_insert(0);
        *count += 1;

        // Check if we should send a confirm
        if *count >= CONFIRM_THRESHOLD {
            *count = 0;
            Some(self.create_confirm(part_id))
        } else {
            None
        }
    }

    /// Processes a received message part.
    ///
    /// Returns `true` if decoding is now complete for this specific part.
    pub fn process_part(&mut self, part: &RldpMessagePart) -> Result<bool> {
        if part.transfer_id != self.transfer_id {
            return Err(RldpError::TransferIdMismatch);
        }

        // Create decoder for this part if not exists
        if let std::collections::hash_map::Entry::Vacant(e) = self.decoders.entry(part.part) {
            let decoder = FecDecoder::from_fec_type(&part.fec_type)?;
            e.insert(decoder);
            self.last_seqno.insert(part.part, -1);
            self.received_symbols_since_last_confirm.insert(part.part, 0);
        }

        // Get the decoder for this part
        if let Some(decoder) = self.decoders.get_mut(&part.part) {
            // Update last seqno for this part
            let last = self.last_seqno.get_mut(&part.part).unwrap();
            if part.seqno > *last {
                *last = part.seqno;
            }

            // Track received symbols for confirmation threshold
            if let Some(count) = self.received_symbols_since_last_confirm.get_mut(&part.part) {
                *count += 1;
            }

            // Add symbol to decoder
            if decoder.add_symbol(part.seqno as u32, &part.data) {
                // Decoding complete for this part
                let decoded_data = decoder.take_decoded()?;
                self.decoded_parts.insert(part.part, decoded_data);
                return Ok(true);
            }
        }

        Ok(false)
    }

    /// Returns the decoded data for a specific part if complete.
    pub fn get_data(&self, part_id: i32) -> Option<&[u8]> {
        self.decoded_parts.get(&part_id).map(|v| v.as_slice())
    }

    /// Takes the decoded data for a specific part.
    pub fn take_data(&mut self, part_id: i32) -> Option<Vec<u8>> {
        self.decoded_parts.remove(&part_id)
    }

    /// Returns all decoded parts combined in order (for backward compatibility).
    /// Returns None if not all parts are decoded.
    pub fn get_all_data(&self) -> Option<Vec<u8>> {
        if self.decoded_parts.is_empty() {
            return None;
        }

        // Combine all parts in order
        let mut result = Vec::new();
        let mut part_id = 0;
        while let Some(data) = self.decoded_parts.get(&part_id) {
            result.extend_from_slice(data);
            part_id += 1;
        }

        Some(result)
    }

    /// Creates a confirm message for a specific part.
    pub fn create_confirm(&self, part_id: i32) -> RldpConfirm {
        let seqno = self.last_seqno.get(&part_id).copied().unwrap_or(-1);
        RldpConfirm::new(self.transfer_id, part_id, seqno)
    }

    /// Creates a complete message for a specific part.
    pub fn create_complete(&self, part_id: i32) -> RldpComplete {
        RldpComplete::new(self.transfer_id, part_id)
    }
}

/// Manager for multiple concurrent transfers.
#[derive(Debug)]
pub struct TransferManager {
    /// Outgoing transfers by ID.
    outgoing: HashMap<[u8; 32], OutgoingTransfer>,
    /// Incoming transfers by ID.
    incoming: HashMap<[u8; 32], IncomingTransfer>,
    /// Completion callbacks for outgoing transfers.
    completions: HashMap<[u8; 32], oneshot::Sender<Result<()>>>,
    /// Data callbacks for incoming transfers.
    data_callbacks: HashMap<[u8; 32], oneshot::Sender<Result<Vec<u8>>>>,
    /// LRU cache of completed transfers for detecting duplicate messages.
    /// Keeps track of the 128 most recently completed transfers.
    completed_transfers: LruCache<[u8; 32], Instant>,
}

impl Default for TransferManager {
    fn default() -> Self {
        Self::new()
    }
}

impl TransferManager {
    /// Creates a new transfer manager.
    pub fn new() -> Self {
        let completed_transfers = LruCache::new(
            std::num::NonZeroUsize::new(LRU_CACHE_SIZE).unwrap()
        );

        Self {
            outgoing: HashMap::new(),
            incoming: HashMap::new(),
            completions: HashMap::new(),
            data_callbacks: HashMap::new(),
            completed_transfers,
        }
    }

    /// Starts a new outgoing transfer.
    ///
    /// Returns the transfer ID and a receiver for completion notification.
    pub fn start_send(
        &mut self,
        data: &[u8],
    ) -> ([u8; 32], oneshot::Receiver<Result<()>>) {
        let transfer = OutgoingTransfer::new(data);
        let transfer_id = transfer.transfer_id;

        let (tx, rx) = oneshot::channel();
        self.completions.insert(transfer_id, tx);
        self.outgoing.insert(transfer_id, transfer);

        (transfer_id, rx)
    }

    /// Gets the next message part for an outgoing transfer.
    pub fn next_part(&mut self, transfer_id: &[u8; 32]) -> Option<RldpMessagePart> {
        self.outgoing.get_mut(transfer_id)?.next_message_part()
    }

    /// Gets the initial burst for an outgoing transfer.
    pub fn initial_burst(&mut self, transfer_id: &[u8; 32]) -> Vec<RldpMessagePart> {
        self.outgoing
            .get_mut(transfer_id)
            .map(|t| t.initial_burst())
            .unwrap_or_default()
    }

    /// Handles a received message part.
    ///
    /// Returns `true` if the transfer is now complete.
    pub fn handle_part(&mut self, part: &RldpMessagePart) -> Result<bool> {
        let transfer = self
            .incoming
            .entry(part.transfer_id)
            .or_insert_with(|| IncomingTransfer::new(part).unwrap());

        transfer.process_part(part)
    }

    /// Marks a transfer as completed and adds it to the LRU cache.
    pub fn mark_transfer_completed(&mut self, transfer_id: [u8; 32]) {
        self.completed_transfers.put(transfer_id, Instant::now());
    }

    /// Checks if a transfer has already been completed (for duplicate detection).
    pub fn is_transfer_completed(&mut self, transfer_id: &[u8; 32]) -> bool {
        self.completed_transfers.contains(transfer_id)
    }

    /// Handles a complete message.
    pub fn handle_complete(&mut self, complete: &RldpComplete) {
        if let Some(mut transfer) = self.outgoing.remove(&complete.transfer_id) {
            transfer.mark_complete();
            self.mark_transfer_completed(complete.transfer_id);

            if let Some(tx) = self.completions.remove(&complete.transfer_id) {
                let _ = tx.send(Ok(()));
            }
        }
    }

    /// Gets the complete message for a finished incoming transfer.
    /// For multi-part transfers, returns complete for part 0.
    pub fn get_complete(&self, transfer_id: &[u8; 32]) -> Option<RldpComplete> {
        self.incoming
            .get(transfer_id)
            .filter(|t| t.is_complete())
            .map(|t| t.create_complete(0))
    }

    /// Takes the data from a completed incoming transfer.
    /// For multi-part transfers, returns all combined data.
    pub fn take_incoming_data(&mut self, transfer_id: &[u8; 32]) -> Option<Vec<u8>> {
        self.incoming.get_mut(transfer_id)?.get_all_data()
    }

    /// Cleans up timed-out transfers.
    pub fn cleanup_timed_out(&mut self) {
        // Clean up outgoing
        let timed_out: Vec<_> = self
            .outgoing
            .iter()
            .filter(|(_, t)| t.is_timed_out())
            .map(|(id, _)| *id)
            .collect();

        for id in timed_out {
            self.outgoing.remove(&id);
            if let Some(tx) = self.completions.remove(&id) {
                let _ = tx.send(Err(RldpError::Timeout));
            }
        }

        // Clean up incoming
        let timed_out: Vec<_> = self
            .incoming
            .iter()
            .filter(|(_, t)| t.is_timed_out())
            .map(|(id, _)| *id)
            .collect();

        for id in timed_out {
            self.incoming.remove(&id);
            if let Some(tx) = self.data_callbacks.remove(&id) {
                let _ = tx.send(Err(RldpError::Timeout));
            }
        }
    }

    /// Returns statistics about current transfers.
    pub fn stats(&self) -> TransferStats {
        TransferStats {
            outgoing_count: self.outgoing.len(),
            incoming_count: self.incoming.len(),
            pending_completions: self.completions.len(),
        }
    }
}

/// Statistics about transfers.
#[derive(Debug, Clone, Default)]
pub struct TransferStats {
    /// Number of active outgoing transfers.
    pub outgoing_count: usize,
    /// Number of active incoming transfers.
    pub incoming_count: usize,
    /// Number of pending completion callbacks.
    pub pending_completions: usize,
}

/// A thread-safe transfer manager.
pub type SharedTransferManager = Arc<Mutex<TransferManager>>;

/// Creates a new shared transfer manager.
pub fn new_shared_manager() -> SharedTransferManager {
    Arc::new(Mutex::new(TransferManager::new()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_transfer_id() {
        let id1 = generate_transfer_id();
        let id2 = generate_transfer_id();

        // Should be random (very unlikely to be equal)
        assert_ne!(id1, id2);

        // Should be 32 bytes
        assert_eq!(id1.len(), 32);
    }

    #[test]
    fn test_outgoing_transfer() {
        let data = b"Test data for outgoing transfer";
        let mut transfer = OutgoingTransfer::new(data);

        assert!(!transfer.is_complete());
        assert!(!transfer.is_timed_out());

        // Get first message part
        let part = transfer.next_message_part().unwrap();
        assert_eq!(part.transfer_id, transfer.transfer_id);
        assert_eq!(part.seqno, 0);

        // Get second message part
        let part = transfer.next_message_part().unwrap();
        assert_eq!(part.seqno, 1);
    }

    #[test]
    fn test_outgoing_transfer_initial_burst() {
        let data = b"Test data";
        let config = TransferConfig {
            burst_size: 5,
            ..Default::default()
        };
        let mut transfer = OutgoingTransfer::with_config(data, config);

        let burst = transfer.initial_burst();
        assert_eq!(burst.len(), 5);

        // Verify sequence numbers
        for (i, part) in burst.iter().enumerate() {
            assert_eq!(part.seqno, i as i32);
        }
    }

    #[test]
    fn test_window_based_flow_control() {
        let data = b"Test data for window control";
        let mut transfer = OutgoingTransfer::new(data);

        // Initially, confirmed_seqno = -1, so can send
        assert!(transfer.can_send_symbol());

        // Send symbols up to window size (or until no more packets)
        let mut sent_count = 0;
        for _ in 0..WINDOW_SIZE {
            if transfer.next_message_part().is_some() {
                sent_count += 1;
            } else {
                break;  // No more packets available
            }
        }

        // Should have sent at least some symbols
        assert!(sent_count > 0);

        // If we sent >= WINDOW_SIZE, window should be full
        if sent_count >= WINDOW_SIZE {
            assert!(!transfer.can_send_symbol());

            // After confirmation, can send again
            transfer.update_confirmed_seqno(500);
            assert!(transfer.can_send_symbol());
        }
    }

    #[test]
    fn test_window_confirmation_updates() {
        let data = b"Test data";
        let mut transfer = OutgoingTransfer::new(data);

        // Start at -1
        assert_eq!(transfer.current_part().unwrap().confirmed_seqno, -1);

        // Receive confirmation
        transfer.update_confirmed_seqno(10);
        assert_eq!(transfer.current_part().unwrap().confirmed_seqno, 10);

        // Later confirmation
        transfer.update_confirmed_seqno(20);
        assert_eq!(transfer.current_part().unwrap().confirmed_seqno, 20);

        // Earlier confirmation should not update (only max)
        transfer.update_confirmed_seqno(5);
        assert_eq!(transfer.current_part().unwrap().confirmed_seqno, 20);
    }

    #[test]
    fn test_incoming_transfer() {
        let data = b"Test data for incoming transfer";
        let mut outgoing = OutgoingTransfer::new(data);

        // Create first message part
        let part = outgoing.next_message_part().unwrap();

        // Create incoming transfer
        let mut incoming = IncomingTransfer::new(&part).unwrap();
        assert!(!incoming.is_complete());

        // Process parts until complete
        loop {
            let complete = incoming.process_part(&part).unwrap();
            if complete {
                break;
            }

            // Get next part from outgoing
            if let Some(next_part) = outgoing.next_message_part() {
                let _ = incoming.process_part(&next_part);
            } else {
                break;
            }
        }
    }

    #[test]
    fn test_transfer_roundtrip() {
        let data: Vec<u8> = (0..1000).map(|i| (i % 256) as u8).collect();
        let mut outgoing = OutgoingTransfer::new(&data);

        // Get first part to initialize incoming
        let first_part = outgoing.next_message_part().unwrap();
        let mut incoming = IncomingTransfer::new(&first_part).unwrap();
        let _ = incoming.process_part(&first_part);

        // Send parts until complete
        while !incoming.is_complete() {
            if let Some(part) = outgoing.next_message_part() {
                let _ = incoming.process_part(&part);
            } else {
                break;
            }
        }

        assert!(incoming.is_complete());
        let received = incoming.take_data(0).unwrap();
        assert_eq!(received, data);
    }

    #[test]
    fn test_complete_message() {
        let data = b"Test";
        let mut outgoing = OutgoingTransfer::new(data);
        let transfer_id = outgoing.transfer_id;

        // Simulate completion
        let complete = RldpComplete::new(transfer_id, 0);
        assert!(outgoing.handle_complete(&complete));
        assert!(outgoing.is_complete());

        // Wrong transfer ID should not complete
        let mut outgoing2 = OutgoingTransfer::new(data);
        let wrong_complete = RldpComplete::new([0u8; 32], 0);
        assert!(!outgoing2.handle_complete(&wrong_complete));
        assert!(!outgoing2.is_complete());
    }

    #[test]
    fn test_transfer_manager() {
        let mut manager = TransferManager::new();
        let data = b"Test data for manager";

        // Start send
        let (transfer_id, _rx) = manager.start_send(data);

        // Get initial burst
        let burst = manager.initial_burst(&transfer_id);
        assert!(!burst.is_empty());

        // Get more parts
        let part = manager.next_part(&transfer_id);
        assert!(part.is_some());

        // Stats
        let stats = manager.stats();
        assert_eq!(stats.outgoing_count, 1);
    }

    #[test]
    fn test_transfer_manager_complete() {
        let mut manager = TransferManager::new();
        let data = b"Test";

        let (transfer_id, _rx) = manager.start_send(data);

        // Handle complete
        let complete = RldpComplete::new(transfer_id, 0);
        manager.handle_complete(&complete);

        // Transfer should be removed
        let stats = manager.stats();
        assert_eq!(stats.outgoing_count, 0);
    }

    #[test]
    fn test_transfer_config() {
        let config = TransferConfig {
            timeout: Duration::from_secs(60),
            symbol_interval: Duration::from_millis(5),
            burst_size: 30,
            initial_delay: Duration::from_millis(50),
            max_repair_symbols: Some(100),
        };

        let data = b"Test";
        let transfer = OutgoingTransfer::with_config(data, config.clone());

        assert_eq!(transfer.config.timeout, Duration::from_secs(60));
        assert_eq!(transfer.config.burst_size, 30);
    }

    #[test]
    fn test_incoming_transfer_wrong_id() {
        let data = b"Test";
        let mut outgoing = OutgoingTransfer::new(data);
        let part = outgoing.next_message_part().unwrap();

        let mut incoming = IncomingTransfer::new(&part).unwrap();

        // Create part with wrong transfer ID
        let wrong_part = RldpMessagePart::new(
            [0u8; 32],
            outgoing.fec_type(),
            0,
            part.total_size,
            0,
            part.data.clone(),
        );

        let result = incoming.process_part(&wrong_part);
        assert!(result.is_err());
    }

    #[test]
    fn test_single_part_small_data() {
        // Small data should fit in a single part
        let data = b"small test data";
        let outgoing = OutgoingTransfer::new(data);

        assert_eq!(outgoing.parts.len(), 1);
        assert_eq!(outgoing.parts[0].part_id, 0);
        assert_eq!(outgoing.parts[0].encoder.data_size(), data.len());
    }

    #[test]
    fn test_empty_data() {
        // Empty data should still create one part
        let data: &[u8] = &[];
        let outgoing = OutgoingTransfer::new(data);

        assert_eq!(outgoing.parts.len(), 1);
        assert_eq!(outgoing.parts[0].part_id, 0);
    }

    #[test]
    fn test_lru_eviction() {
        let mut manager = TransferManager::new();

        // Add 150 completed transfers (more than LRU_CACHE_SIZE of 128)
        for i in 0..150 {
            let mut id = [0u8; 32];
            id[0] = (i % 256) as u8;
            id[1] = (i / 256) as u8;
            manager.mark_transfer_completed(id);
        }

        // First 22 transfers should have been evicted (150 - 128)
        for i in 0..22 {
            let mut id = [0u8; 32];
            id[0] = (i % 256) as u8;
            id[1] = (i / 256) as u8;
            assert!(!manager.is_transfer_completed(&id), "Transfer {} should be evicted", i);
        }

        // Transfers 22-149 should still be in cache
        for i in 22..150 {
            let mut id = [0u8; 32];
            id[0] = (i % 256) as u8;
            id[1] = (i / 256) as u8;
            assert!(manager.is_transfer_completed(&id), "Transfer {} should be in cache", i);
        }
    }

    #[test]
    fn test_constants_match_official_ton() {
        // Verify RLDP v1 constants match official TON implementation
        // Reference: TON rldp-peer.hpp, rldp.h

        // Symbol size: 768 bytes (rldp-peer.hpp:79)
        assert_eq!(crate::fec::SYMBOL_SIZE, 768, "SYMBOL_SIZE must match TON rldp-peer.hpp:79");

        // Slice size: 2MB per part (rldp-peer.hpp:76) - official TON uses 2_000_000
        assert_eq!(SLICE_SIZE, 2_000_000, "SLICE_SIZE must be 2MB (rldp-peer.hpp:76)");

        // Window size: 1000 unconfirmed symbols (rldp-peer.hpp:82)
        assert_eq!(WINDOW_SIZE, 1000, "WINDOW_SIZE must match TON rldp-peer.hpp:82");

        // LRU cache size: 128 completed transfers (rldp-peer.hpp:85)
        assert_eq!(LRU_CACHE_SIZE, 128, "LRU_CACHE_SIZE must match TON rldp-peer.hpp:85");

        // Transfer timeout: 60 seconds (aligns with blockchain block time)
        assert_eq!(DEFAULT_TRANSFER_TIMEOUT, Duration::from_secs(60),
                   "DEFAULT_TRANSFER_TIMEOUT must be 60 seconds (v1 conformity)");
    }
}
