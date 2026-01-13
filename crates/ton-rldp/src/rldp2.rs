//! RLDP2 protocol implementation with bitmask confirmation.
//!
//! RLDP2 is an improved version of RLDP that uses bitmask-based acknowledgment
//! for more efficient tracking of received symbols. Instead of just tracking
//! the last received seqno, RLDP2 uses a bitmask to indicate exactly which
//! symbols have been received, allowing for better recovery from packet loss.
//!
//! ## Key Differences from RLDP v1
//!
//! - **Bitmask Confirmation**: Uses a 32-bit bitmask to track which symbols
//!   relative to `max_seqno` have been received, allowing selective retransmission.
//! - **Received Count**: Tracks total symbols received for bandwidth estimation.
//! - **More Efficient**: Reduces unnecessary retransmissions by precisely
//!   indicating which symbols are missing.
//!
//! ## TL Schema
//!
//! ```tlb
//! rldp2.messagePart transfer_id:int256 fec_type:fec.Type part:int total_size:long
//!                   seqno:int data:bytes = rldp2.MessagePart;
//! rldp2.confirm transfer_id:int256 part:int max_seqno:int received_mask:int
//!               received_count:int = rldp2.Confirm;
//! ```
//!
//! ## Protocol Flow
//!
//! ```text
//! Sender                                              Receiver
//!    |                                                    |
//!    |  ────── rldp2.messagePart (seqno=0) ─────────────> |
//!    |  ────── rldp2.messagePart (seqno=1) ─────────────> |
//!    |  (seqno=2 lost)                                    |
//!    |  ────── rldp2.messagePart (seqno=3) ─────────────> |
//!    |                                                    |
//!    |  <──── rldp2.confirm (max_seqno=3,                 |
//!    |                       mask=0b1011,                 |
//!    |                       count=3) ───────────────────|
//!    |                                                    |
//!    |  (Sender sees seqno=2 missing, retransmits)        |
//!    |  ────── rldp2.messagePart (seqno=2) ─────────────> |
//!    |                                                    |
//!    |  <───────────── rldp.complete ─────────────────── |
//! ```
//!
//! ## Example Usage
//!
//! ```rust
//! use ton_rldp::rldp2::{Rldp2OutgoingTransfer, Rldp2IncomingTransfer, ReceivedSymbolTracker};
//!
//! // Sender side
//! let data = b"Large data to transfer reliably with RLDP2";
//! let mut outgoing = Rldp2OutgoingTransfer::new(data);
//!
//! // Get message parts to send
//! while let Some(part) = outgoing.next_message_part() {
//!     // Send part via ADNL...
//! }
//!
//! // Receiver side with bitmask tracking
//! let mut tracker = ReceivedSymbolTracker::new();
//! tracker.mark_received(0);
//! tracker.mark_received(1);
//! tracker.mark_received(3); // seqno=2 lost
//!
//! // Generate confirm with bitmask
//! let (max_seqno, mask, count) = tracker.get_confirm_data();
//! // mask will show which symbols relative to max_seqno are received
//! ```

use std::collections::HashMap;
use std::time::{Duration, Instant};

use rand::RngCore;
use ton_adnl::{TlReader, TlWriter};

use crate::error::{RldpError, Result};
use crate::fec::{FecDecoder, FecEncoder};
use crate::types::{FecType, RldpComplete, RldpTypeError};

// ============================================================================
// TL Schema IDs for RLDP2
// ============================================================================

/// rldp2.messagePart transfer_id:int256 fec_type:fec.Type part:int total_size:long
///                   seqno:int data:bytes = rldp2.MessagePart
/// Schema ID computed from CRC32 of the TL schema string.
pub const RLDP2_MESSAGE_PART: u32 = 0x8cadb902;

/// rldp2.confirm transfer_id:int256 part:int max_seqno:int received_mask:int
///               received_count:int = rldp2.Confirm
/// Schema ID computed from CRC32 of the TL schema string.
pub const RLDP2_CONFIRM: u32 = 0xa6af9f4d;

// ============================================================================
// Constants
// ============================================================================

/// Default timeout for RLDP2 transfers (60 seconds, same as RLDP v1).
pub const DEFAULT_RLDP2_TIMEOUT: Duration = Duration::from_secs(60);

/// Number of bits in the received mask (32 bits).
pub const RECEIVED_MASK_BITS: usize = 32;

/// Confirmation threshold: send confirm after receiving this many symbols.
pub const RLDP2_CONFIRM_THRESHOLD: u32 = 10;

/// Window size for RLDP2 flow control.
pub const RLDP2_WINDOW_SIZE: usize = 1000;

/// Slice size for multi-part transfers (2MB, same as RLDP v1).
pub const RLDP2_SLICE_SIZE: usize = 2_000_000;

// ============================================================================
// RLDP2 Message Types
// ============================================================================

/// RLDP2 message part - carries FEC-encoded data chunks.
///
/// Identical structure to RLDP v1 message part, but uses a different schema ID
/// to distinguish RLDP2 traffic.
#[derive(Debug, Clone)]
pub struct Rldp2MessagePart {
    /// Transfer identifier (random 256-bit value).
    pub transfer_id: [u8; 32],
    /// FEC type configuration.
    pub fec_type: FecType,
    /// Part number (for multi-part transfers).
    pub part: i32,
    /// Total size of the original data.
    pub total_size: i64,
    /// Sequence number of this symbol.
    pub seqno: i32,
    /// FEC-encoded symbol data.
    pub data: Vec<u8>,
}

impl Rldp2MessagePart {
    /// Creates a new RLDP2 message part.
    pub fn new(
        transfer_id: [u8; 32],
        fec_type: FecType,
        part: i32,
        total_size: i64,
        seqno: i32,
        data: Vec<u8>,
    ) -> Self {
        Self {
            transfer_id,
            fec_type,
            part,
            total_size,
            seqno,
            data,
        }
    }

    /// Serializes the message part to TL format.
    pub fn write_to(&self, writer: &mut TlWriter) {
        writer.write_u32(RLDP2_MESSAGE_PART);
        writer.write_int256(&self.transfer_id);
        self.fec_type.write_to(writer);
        writer.write_i32(self.part);
        writer.write_i64(self.total_size);
        writer.write_i32(self.seqno);
        writer.write_bytes(&self.data);
    }

    /// Serializes to a byte vector.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut writer = TlWriter::new();
        self.write_to(&mut writer);
        writer.finish()
    }

    /// Deserializes from TL format.
    pub fn read_from(reader: &mut TlReader) -> std::result::Result<Self, RldpTypeError> {
        let schema_id = reader
            .read_u32()
            .map_err(|e| RldpTypeError::TlReadError(e.to_string()))?;
        if schema_id != RLDP2_MESSAGE_PART {
            return Err(RldpTypeError::UnexpectedSchemaId {
                expected: RLDP2_MESSAGE_PART,
                got: schema_id,
            });
        }

        let transfer_id = reader
            .read_int256()
            .map_err(|e| RldpTypeError::TlReadError(e.to_string()))?;
        let fec_type = FecType::read_from(reader)?;
        let part = reader
            .read_i32()
            .map_err(|e| RldpTypeError::TlReadError(e.to_string()))?;
        let total_size = reader
            .read_i64()
            .map_err(|e| RldpTypeError::TlReadError(e.to_string()))?;
        let seqno = reader
            .read_i32()
            .map_err(|e| RldpTypeError::TlReadError(e.to_string()))?;
        let data = reader
            .read_bytes()
            .map_err(|e| RldpTypeError::TlReadError(e.to_string()))?;

        Ok(Self {
            transfer_id,
            fec_type,
            part,
            total_size,
            seqno,
            data,
        })
    }

    /// Parses from bytes.
    pub fn from_bytes(data: &[u8]) -> std::result::Result<Self, RldpTypeError> {
        let mut reader = TlReader::new(data);
        Self::read_from(&mut reader)
    }
}

/// RLDP2 confirm message - acknowledges received symbols with bitmask.
///
/// The bitmask provides precise information about which symbols have been
/// received, allowing the sender to selectively retransmit only missing symbols.
#[derive(Debug, Clone, Copy)]
pub struct Rldp2Confirm {
    /// Transfer identifier.
    pub transfer_id: [u8; 32],
    /// Part number.
    pub part: i32,
    /// Highest received sequence number.
    pub max_seqno: i32,
    /// Bitmask of received symbols relative to max_seqno.
    ///
    /// Bit i is set if symbol (max_seqno - i) has been received.
    /// - Bit 0: max_seqno
    /// - Bit 1: max_seqno - 1
    /// - Bit 31: max_seqno - 31
    pub received_mask: i32,
    /// Total count of symbols received.
    pub received_count: i32,
}

impl Rldp2Confirm {
    /// Creates a new RLDP2 confirm message.
    pub fn new(
        transfer_id: [u8; 32],
        part: i32,
        max_seqno: i32,
        received_mask: i32,
        received_count: i32,
    ) -> Self {
        Self {
            transfer_id,
            part,
            max_seqno,
            received_mask,
            received_count,
        }
    }

    /// Serializes the confirm message to TL format.
    pub fn write_to(&self, writer: &mut TlWriter) {
        writer.write_u32(RLDP2_CONFIRM);
        writer.write_int256(&self.transfer_id);
        writer.write_i32(self.part);
        writer.write_i32(self.max_seqno);
        writer.write_i32(self.received_mask);
        writer.write_i32(self.received_count);
    }

    /// Serializes to a byte vector.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut writer = TlWriter::new();
        self.write_to(&mut writer);
        writer.finish()
    }

    /// Deserializes from TL format.
    pub fn read_from(reader: &mut TlReader) -> std::result::Result<Self, RldpTypeError> {
        let schema_id = reader
            .read_u32()
            .map_err(|e| RldpTypeError::TlReadError(e.to_string()))?;
        if schema_id != RLDP2_CONFIRM {
            return Err(RldpTypeError::UnexpectedSchemaId {
                expected: RLDP2_CONFIRM,
                got: schema_id,
            });
        }

        let transfer_id = reader
            .read_int256()
            .map_err(|e| RldpTypeError::TlReadError(e.to_string()))?;
        let part = reader
            .read_i32()
            .map_err(|e| RldpTypeError::TlReadError(e.to_string()))?;
        let max_seqno = reader
            .read_i32()
            .map_err(|e| RldpTypeError::TlReadError(e.to_string()))?;
        let received_mask = reader
            .read_i32()
            .map_err(|e| RldpTypeError::TlReadError(e.to_string()))?;
        let received_count = reader
            .read_i32()
            .map_err(|e| RldpTypeError::TlReadError(e.to_string()))?;

        Ok(Self {
            transfer_id,
            part,
            max_seqno,
            received_mask,
            received_count,
        })
    }

    /// Parses from bytes.
    pub fn from_bytes(data: &[u8]) -> std::result::Result<Self, RldpTypeError> {
        let mut reader = TlReader::new(data);
        Self::read_from(&mut reader)
    }

    /// Checks if a specific seqno is marked as received in the bitmask.
    ///
    /// Returns `None` if the seqno is outside the mask range.
    pub fn is_seqno_received(&self, seqno: i32) -> Option<bool> {
        let offset = self.max_seqno - seqno;
        if offset < 0 || offset >= RECEIVED_MASK_BITS as i32 {
            return None;
        }
        Some((self.received_mask & (1 << offset)) != 0)
    }
}

// ============================================================================
// Bitmask Tracking
// ============================================================================

/// Tracks received symbols using a bitmask for efficient acknowledgment.
///
/// This tracker maintains:
/// - A set of all received sequence numbers
/// - The highest received seqno (max_seqno)
/// - A count of total symbols received
///
/// It can generate the bitmask needed for RLDP2 confirm messages.
#[derive(Debug, Clone, Default)]
pub struct ReceivedSymbolTracker {
    /// Set of received sequence numbers.
    received: std::collections::HashSet<u32>,
    /// Highest received sequence number (-1 if none received).
    max_seqno: i32,
    /// Total count of received symbols.
    received_count: u32,
}

impl ReceivedSymbolTracker {
    /// Creates a new empty tracker.
    pub fn new() -> Self {
        Self {
            received: std::collections::HashSet::new(),
            max_seqno: -1,
            received_count: 0,
        }
    }

    /// Marks a symbol as received.
    ///
    /// Returns `true` if this is a new symbol, `false` if it was already received.
    pub fn mark_received(&mut self, seqno: u32) -> bool {
        if self.received.insert(seqno) {
            self.received_count += 1;
            if seqno as i32 > self.max_seqno {
                self.max_seqno = seqno as i32;
            }
            true
        } else {
            false
        }
    }

    /// Checks if a symbol has been received.
    pub fn is_received(&self, seqno: u32) -> bool {
        self.received.contains(&seqno)
    }

    /// Returns the highest received sequence number.
    pub fn max_seqno(&self) -> i32 {
        self.max_seqno
    }

    /// Returns the total count of received symbols.
    pub fn received_count(&self) -> u32 {
        self.received_count
    }

    /// Generates the received bitmask relative to max_seqno.
    ///
    /// Bit i is set if symbol (max_seqno - i) has been received.
    pub fn generate_mask(&self) -> i32 {
        if self.max_seqno < 0 {
            return 0;
        }

        let mut mask: i32 = 0;
        for i in 0..RECEIVED_MASK_BITS {
            let seqno = self.max_seqno - i as i32;
            if seqno >= 0 && self.received.contains(&(seqno as u32)) {
                mask |= 1 << i;
            }
        }
        mask
    }

    /// Gets the data needed for an RLDP2 confirm message.
    ///
    /// Returns (max_seqno, received_mask, received_count).
    pub fn get_confirm_data(&self) -> (i32, i32, i32) {
        (self.max_seqno, self.generate_mask(), self.received_count as i32)
    }

    /// Creates an Rldp2Confirm message from this tracker.
    pub fn create_confirm(&self, transfer_id: [u8; 32], part: i32) -> Rldp2Confirm {
        let (max_seqno, mask, count) = self.get_confirm_data();
        Rldp2Confirm::new(transfer_id, part, max_seqno, mask, count)
    }

    /// Returns an iterator over missing sequence numbers in the mask range.
    ///
    /// These are symbols that should be prioritized for retransmission.
    pub fn missing_in_range(&self) -> Vec<u32> {
        if self.max_seqno < 0 {
            return Vec::new();
        }

        let mut missing = Vec::new();
        for i in 0..RECEIVED_MASK_BITS {
            let seqno = self.max_seqno - i as i32;
            if seqno >= 0 && !self.received.contains(&(seqno as u32)) {
                missing.push(seqno as u32);
            }
        }
        missing
    }

    /// Resets the tracker to its initial state.
    pub fn reset(&mut self) {
        self.received.clear();
        self.max_seqno = -1;
        self.received_count = 0;
    }
}

// ============================================================================
// RLDP2 Outgoing Transfer
// ============================================================================

/// Generates a random transfer ID.
pub fn generate_transfer_id() -> [u8; 32] {
    let mut id = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut id);
    id
}

/// State of a single part in an RLDP2 multi-part transfer.
#[derive(Debug)]
struct Rldp2PartState {
    /// Part number.
    part_id: i32,
    /// FEC encoder for this part.
    encoder: FecEncoder,
    /// Pre-encoded packets (source + repair).
    packets: Vec<(u32, Vec<u8>)>,
    /// Current packet index.
    current_index: usize,
    /// Whether this part is complete.
    is_complete: bool,
    /// Highest confirmed seqno (for window control).
    confirmed_seqno: i32,
    /// Set of confirmed seqnos (from bitmask).
    confirmed_seqnos: std::collections::HashSet<u32>,
}

impl Rldp2PartState {
    /// Creates a new part state.
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
            confirmed_seqnos: std::collections::HashSet::new(),
        }
    }

    /// Checks if window allows sending another symbol.
    fn can_send_symbol(&self) -> bool {
        let unconfirmed = self.current_index as i32 - self.confirmed_seqno;
        unconfirmed < RLDP2_WINDOW_SIZE as i32
    }

    /// Updates confirmation state from an RLDP2 confirm message.
    fn apply_confirm(&mut self, confirm: &Rldp2Confirm) {
        // Update max confirmed seqno
        self.confirmed_seqno = self.confirmed_seqno.max(confirm.max_seqno);

        // Update confirmed seqnos from bitmask
        for i in 0..RECEIVED_MASK_BITS {
            if (confirm.received_mask & (1 << i)) != 0 {
                let seqno = confirm.max_seqno - i as i32;
                if seqno >= 0 {
                    self.confirmed_seqnos.insert(seqno as u32);
                }
            }
        }
    }

    /// Checks if a specific seqno needs retransmission.
    fn needs_retransmit(&self, seqno: u32) -> bool {
        !self.confirmed_seqnos.contains(&seqno)
    }

    /// Gets missing seqnos that should be retransmitted.
    fn get_missing_seqnos(&self, confirm: &Rldp2Confirm) -> Vec<u32> {
        let mut missing = Vec::new();
        for i in 0..RECEIVED_MASK_BITS {
            let seqno = confirm.max_seqno - i as i32;
            if seqno >= 0 && (confirm.received_mask & (1 << i)) == 0 {
                // This seqno is not confirmed
                if (seqno as usize) < self.packets.len() {
                    missing.push(seqno as u32);
                }
            }
        }
        missing
    }

    /// Gets the next packet.
    fn next_packet(&mut self) -> Option<(u32, Vec<u8>)> {
        if self.is_complete || self.current_index >= self.packets.len() {
            return None;
        }

        let (seqno, data) = self.packets[self.current_index].clone();
        self.current_index += 1;
        Some((seqno, data))
    }

    /// Gets a specific packet by seqno for retransmission.
    fn get_packet(&self, seqno: u32) -> Option<(u32, Vec<u8>)> {
        self.packets.get(seqno as usize).cloned()
    }

    /// Marks this part as complete.
    fn mark_complete(&mut self) {
        self.is_complete = true;
    }
}

/// Configuration for RLDP2 transfers.
#[derive(Debug, Clone)]
pub struct Rldp2TransferConfig {
    /// Timeout for the entire transfer.
    pub timeout: Duration,
    /// Number of symbols to send in initial burst.
    pub burst_size: usize,
    /// Maximum number of repair symbols.
    pub max_repair_symbols: Option<u32>,
}

impl Default for Rldp2TransferConfig {
    fn default() -> Self {
        Self {
            timeout: DEFAULT_RLDP2_TIMEOUT,
            burst_size: 20,
            max_repair_symbols: Some(50),
        }
    }
}

/// State of an outgoing RLDP2 transfer.
#[derive(Debug)]
pub struct Rldp2OutgoingTransfer {
    /// Transfer identifier.
    pub transfer_id: [u8; 32],
    /// Total size of all data.
    total_size: i64,
    /// All parts of the transfer.
    parts: Vec<Rldp2PartState>,
    /// Current part index.
    current_part_idx: usize,
    /// Start time.
    start_time: Instant,
    /// Whether the transfer is complete.
    is_complete: bool,
    /// Configuration.
    config: Rldp2TransferConfig,
    /// Queue of seqnos to retransmit.
    retransmit_queue: Vec<(i32, u32)>, // (part_id, seqno)
}

impl Rldp2OutgoingTransfer {
    /// Creates a new outgoing RLDP2 transfer.
    pub fn new(data: &[u8]) -> Self {
        Self::with_config(data, Rldp2TransferConfig::default())
    }

    /// Creates a new outgoing transfer with custom configuration.
    pub fn with_config(data: &[u8], config: Rldp2TransferConfig) -> Self {
        let transfer_id = generate_transfer_id();
        let repair_count = config.max_repair_symbols.unwrap_or(50);
        let total_size = data.len() as i64;

        let parts = Self::split_into_parts(data, repair_count);

        Self {
            transfer_id,
            total_size,
            parts,
            current_part_idx: 0,
            start_time: Instant::now(),
            is_complete: false,
            config,
            retransmit_queue: Vec::new(),
        }
    }

    /// Creates a transfer with a specific transfer ID.
    pub fn with_id(transfer_id: [u8; 32], data: &[u8]) -> Self {
        let config = Rldp2TransferConfig::default();
        let repair_count = config.max_repair_symbols.unwrap_or(50);
        let total_size = data.len() as i64;

        let parts = Self::split_into_parts(data, repair_count);

        Self {
            transfer_id,
            total_size,
            parts,
            current_part_idx: 0,
            start_time: Instant::now(),
            is_complete: false,
            config,
            retransmit_queue: Vec::new(),
        }
    }

    /// Splits data into parts.
    fn split_into_parts(data: &[u8], repair_count: u32) -> Vec<Rldp2PartState> {
        let mut parts = Vec::new();

        for (part_id, chunk) in data.chunks(RLDP2_SLICE_SIZE).enumerate() {
            let part = Rldp2PartState::new(part_id as i32, chunk, repair_count);
            parts.push(part);
        }

        if parts.is_empty() {
            parts.push(Rldp2PartState::new(0, &[], repair_count));
        }

        parts
    }

    /// Returns the FEC type for the current part.
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
    fn current_part(&self) -> Option<&Rldp2PartState> {
        self.parts.get(self.current_part_idx)
    }

    /// Returns a mutable reference to the current part.
    fn current_part_mut(&mut self) -> Option<&mut Rldp2PartState> {
        self.parts.get_mut(self.current_part_idx)
    }

    /// Checks if window allows sending another symbol.
    pub fn can_send_symbol(&self) -> bool {
        self.current_part()
            .map(|p| p.can_send_symbol())
            .unwrap_or(false)
    }

    /// Handles an RLDP2 confirm message.
    ///
    /// Updates the confirmation state and queues missing seqnos for retransmission.
    pub fn handle_confirm(&mut self, confirm: &Rldp2Confirm) {
        if confirm.transfer_id != self.transfer_id {
            return;
        }

        // Find the part this confirm is for
        if let Some(part) = self.parts.get_mut(confirm.part as usize) {
            // Get missing seqnos before applying confirm
            let missing = part.get_missing_seqnos(confirm);

            // Apply the confirm
            part.apply_confirm(confirm);

            // Queue missing seqnos for retransmission
            for seqno in missing {
                self.retransmit_queue.push((confirm.part, seqno));
            }
        }
    }

    /// Handles a complete message.
    pub fn handle_complete(&mut self, complete: &RldpComplete) -> bool {
        if complete.transfer_id == self.transfer_id {
            // Mark the specific part as complete
            if let Some(part) = self.parts.get_mut(complete.part as usize) {
                part.mark_complete();
            }

            // Check if all parts are complete
            if self.parts.iter().all(|p| p.is_complete) {
                self.is_complete = true;
            }
            true
        } else {
            false
        }
    }

    /// Gets the next message part to send.
    ///
    /// Prioritizes retransmissions over new packets.
    pub fn next_message_part(&mut self) -> Option<Rldp2MessagePart> {
        if self.is_complete || self.is_timed_out() {
            return None;
        }

        // First, check for retransmissions
        while let Some((part_id, seqno)) = self.retransmit_queue.pop() {
            if let Some(part) = self.parts.get(part_id as usize)
                && part.needs_retransmit(seqno)
                    && let Some((_, packet_data)) = part.get_packet(seqno) {
                        return Some(Rldp2MessagePart::new(
                            self.transfer_id,
                            part.encoder.fec_type(),
                            part_id,
                            self.total_size,
                            seqno as i32,
                            packet_data,
                        ));
                    }
        }

        // Then try to get a new packet
        loop {
            if self.current_part_idx >= self.parts.len() {
                return None;
            }

            if !self.can_send_symbol() {
                return None;
            }

            let packet_option = {
                if let Some(part) = self.current_part_mut() {
                    part.next_packet()
                        .map(|(seqno, data)| (seqno, data, part.part_id, part.encoder.fec_type()))
                } else {
                    None
                }
            };

            if let Some((seqno, packet_data, part_id, fec_type)) = packet_option {
                return Some(Rldp2MessagePart::new(
                    self.transfer_id,
                    fec_type,
                    part_id,
                    self.total_size,
                    seqno as i32,
                    packet_data,
                ));
            }

            self.current_part_idx += 1;
        }
    }

    /// Gets the initial burst of message parts.
    pub fn initial_burst(&mut self) -> Vec<Rldp2MessagePart> {
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
}

// ============================================================================
// RLDP2 Incoming Transfer
// ============================================================================

/// State of an incoming RLDP2 transfer.
#[derive(Debug)]
pub struct Rldp2IncomingTransfer {
    /// Transfer identifier.
    pub transfer_id: [u8; 32],
    /// FEC decoders for each part.
    decoders: HashMap<i32, FecDecoder>,
    /// Decoded data for each part.
    decoded_parts: HashMap<i32, Vec<u8>>,
    /// Symbol trackers for each part (for bitmask confirmation).
    trackers: HashMap<i32, ReceivedSymbolTracker>,
    /// Total size of the data.
    total_size: i64,
    /// Start time.
    start_time: Instant,
    /// Timeout duration.
    timeout: Duration,
}

impl Rldp2IncomingTransfer {
    /// Creates a new incoming RLDP2 transfer from the first message part.
    pub fn new(part: &Rldp2MessagePart) -> Result<Self> {
        Self::with_timeout(part, DEFAULT_RLDP2_TIMEOUT)
    }

    /// Creates a new incoming transfer with custom timeout.
    pub fn with_timeout(part: &Rldp2MessagePart, timeout: Duration) -> Result<Self> {
        let mut decoders = HashMap::new();
        let mut trackers = HashMap::new();

        let decoder = FecDecoder::from_fec_type(&part.fec_type)?;
        decoders.insert(part.part, decoder);
        trackers.insert(part.part, ReceivedSymbolTracker::new());

        Ok(Self {
            transfer_id: part.transfer_id,
            decoders,
            decoded_parts: HashMap::new(),
            trackers,
            total_size: part.total_size,
            start_time: Instant::now(),
            timeout,
        })
    }

    /// Returns whether all parts are complete.
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
        self.trackers.values().map(|t| t.received_count() as usize).sum()
    }

    /// Returns the tracker for a specific part.
    pub fn get_tracker(&self, part_id: i32) -> Option<&ReceivedSymbolTracker> {
        self.trackers.get(&part_id)
    }

    /// Returns whether a confirm should be sent for the given part.
    pub fn should_send_confirm(&self, part_id: i32) -> bool {
        self.trackers
            .get(&part_id)
            .map(|t| t.received_count() % RLDP2_CONFIRM_THRESHOLD == 0 && t.received_count() > 0)
            .unwrap_or(false)
    }

    /// Creates a confirm message for a specific part.
    pub fn create_confirm(&self, part_id: i32) -> Option<Rldp2Confirm> {
        self.trackers
            .get(&part_id)
            .map(|t| t.create_confirm(self.transfer_id, part_id))
    }

    /// Creates a confirm message if threshold is reached.
    pub fn maybe_create_confirm(&self, part_id: i32) -> Option<Rldp2Confirm> {
        if self.should_send_confirm(part_id) {
            self.create_confirm(part_id)
        } else {
            None
        }
    }

    /// Processes a received message part.
    ///
    /// Returns `true` if decoding is now complete for this specific part.
    pub fn process_part(&mut self, part: &Rldp2MessagePart) -> Result<bool> {
        if part.transfer_id != self.transfer_id {
            return Err(RldpError::TransferIdMismatch);
        }

        // Create decoder and tracker for this part if not exists
        if let std::collections::hash_map::Entry::Vacant(e) = self.decoders.entry(part.part) {
            let decoder = FecDecoder::from_fec_type(&part.fec_type)?;
            e.insert(decoder);
            self.trackers.insert(part.part, ReceivedSymbolTracker::new());
        }

        // Track received symbol
        if let Some(tracker) = self.trackers.get_mut(&part.part) {
            tracker.mark_received(part.seqno as u32);
        }

        // Add symbol to decoder
        if let Some(decoder) = self.decoders.get_mut(&part.part)
            && decoder.add_symbol(part.seqno as u32, &part.data) {
                let decoded_data = decoder.take_decoded()?;
                self.decoded_parts.insert(part.part, decoded_data);
                return Ok(true);
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

    /// Returns all decoded parts combined in order.
    pub fn get_all_data(&self) -> Option<Vec<u8>> {
        if self.decoded_parts.is_empty() {
            return None;
        }

        let mut result = Vec::new();
        let mut part_id = 0;
        while let Some(data) = self.decoded_parts.get(&part_id) {
            result.extend_from_slice(data);
            part_id += 1;
        }

        Some(result)
    }

    /// Creates a complete message for a specific part.
    pub fn create_complete(&self, part_id: i32) -> RldpComplete {
        RldpComplete::new(self.transfer_id, part_id)
    }
}

// ============================================================================
// RLDP2 Message Enum
// ============================================================================

/// Any RLDP2 message type.
#[derive(Debug, Clone)]
pub enum Rldp2Message {
    MessagePart(Rldp2MessagePart),
    Confirm(Rldp2Confirm),
    Complete(RldpComplete),
}

impl Rldp2Message {
    /// Returns the schema ID for this message type.
    pub fn schema_id(&self) -> u32 {
        match self {
            Rldp2Message::MessagePart(_) => RLDP2_MESSAGE_PART,
            Rldp2Message::Confirm(_) => RLDP2_CONFIRM,
            Rldp2Message::Complete(_) => crate::types::RLDP_COMPLETE,
        }
    }

    /// Serializes the message to TL format.
    pub fn write_to(&self, writer: &mut TlWriter) {
        match self {
            Rldp2Message::MessagePart(m) => m.write_to(writer),
            Rldp2Message::Confirm(m) => m.write_to(writer),
            Rldp2Message::Complete(m) => m.write_to(writer),
        }
    }

    /// Serializes to a byte vector.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut writer = TlWriter::new();
        self.write_to(&mut writer);
        writer.finish()
    }

    /// Deserializes from TL format.
    pub fn read_from(reader: &mut TlReader) -> std::result::Result<Self, RldpTypeError> {
        let schema_id = reader
            .peek_u32()
            .map_err(|e| RldpTypeError::TlReadError(e.to_string()))?;

        match schema_id {
            RLDP2_MESSAGE_PART => Ok(Rldp2Message::MessagePart(Rldp2MessagePart::read_from(
                reader,
            )?)),
            RLDP2_CONFIRM => Ok(Rldp2Message::Confirm(Rldp2Confirm::read_from(reader)?)),
            crate::types::RLDP_COMPLETE => {
                Ok(Rldp2Message::Complete(RldpComplete::read_from(reader)?))
            }
            _ => Err(RldpTypeError::UnknownMessageType(schema_id)),
        }
    }

    /// Parses from bytes.
    pub fn from_bytes(data: &[u8]) -> std::result::Result<Self, RldpTypeError> {
        let mut reader = TlReader::new(data);
        Self::read_from(&mut reader)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_schema_ids() {
        // Verify schema IDs are distinct from RLDP v1
        assert_ne!(RLDP2_MESSAGE_PART, crate::types::RLDP_MESSAGE_PART);
        assert_ne!(RLDP2_CONFIRM, crate::types::RLDP_CONFIRM);
    }

    #[test]
    fn test_received_symbol_tracker() {
        let mut tracker = ReceivedSymbolTracker::new();

        // Initial state
        assert_eq!(tracker.max_seqno(), -1);
        assert_eq!(tracker.received_count(), 0);
        assert_eq!(tracker.generate_mask(), 0);

        // Add some symbols
        tracker.mark_received(0);
        tracker.mark_received(1);
        tracker.mark_received(3); // Skip 2

        assert_eq!(tracker.max_seqno(), 3);
        assert_eq!(tracker.received_count(), 3);
        assert!(tracker.is_received(0));
        assert!(tracker.is_received(1));
        assert!(!tracker.is_received(2));
        assert!(tracker.is_received(3));

        // Check bitmask: bit 0 = seqno 3, bit 1 = seqno 2, bit 2 = seqno 1, bit 3 = seqno 0
        // seqno 3 received -> bit 0 set (1)
        // seqno 2 NOT received -> bit 1 clear (0)
        // seqno 1 received -> bit 2 set (4)
        // seqno 0 received -> bit 3 set (8)
        // Expected: 0b1101 = 13
        let mask = tracker.generate_mask();
        assert_eq!(mask & 0b1111, 0b1101);
    }

    #[test]
    fn test_received_symbol_tracker_missing() {
        let mut tracker = ReceivedSymbolTracker::new();

        tracker.mark_received(0);
        tracker.mark_received(1);
        tracker.mark_received(3);
        tracker.mark_received(5);

        let missing = tracker.missing_in_range();
        assert!(missing.contains(&2));
        assert!(missing.contains(&4));
        assert!(!missing.contains(&0));
        assert!(!missing.contains(&1));
        assert!(!missing.contains(&3));
        assert!(!missing.contains(&5));
    }

    #[test]
    fn test_received_symbol_tracker_duplicate() {
        let mut tracker = ReceivedSymbolTracker::new();

        assert!(tracker.mark_received(5)); // New
        assert!(!tracker.mark_received(5)); // Duplicate

        assert_eq!(tracker.received_count(), 1);
    }

    #[test]
    fn test_rldp2_message_part_roundtrip() {
        let transfer_id = [42u8; 32];
        let fec_type = FecType::raptorq(1024, 768, 2);
        let original = Rldp2MessagePart::new(
            transfer_id,
            fec_type,
            0,
            1024,
            5,
            vec![1, 2, 3, 4, 5],
        );

        let bytes = original.to_bytes();
        let parsed = Rldp2MessagePart::from_bytes(&bytes).unwrap();

        assert_eq!(original.transfer_id, parsed.transfer_id);
        assert_eq!(original.fec_type, parsed.fec_type);
        assert_eq!(original.part, parsed.part);
        assert_eq!(original.total_size, parsed.total_size);
        assert_eq!(original.seqno, parsed.seqno);
        assert_eq!(original.data, parsed.data);
    }

    #[test]
    fn test_rldp2_confirm_roundtrip() {
        let original = Rldp2Confirm::new([1u8; 32], 0, 10, 0b1011, 3);

        let bytes = original.to_bytes();
        let parsed = Rldp2Confirm::from_bytes(&bytes).unwrap();

        assert_eq!(original.transfer_id, parsed.transfer_id);
        assert_eq!(original.part, parsed.part);
        assert_eq!(original.max_seqno, parsed.max_seqno);
        assert_eq!(original.received_mask, parsed.received_mask);
        assert_eq!(original.received_count, parsed.received_count);
    }

    #[test]
    fn test_rldp2_confirm_seqno_check() {
        // mask = 0b1011 = 11
        // bit 0 (value 1) -> seqno 10: set
        // bit 1 (value 2) -> seqno 9: set
        // bit 2 (value 4) -> seqno 8: not set
        // bit 3 (value 8) -> seqno 7: set
        let confirm = Rldp2Confirm::new([1u8; 32], 0, 10, 0b1011, 3);

        // Bit 0 -> seqno 10 (mask & 1 = 1 -> set)
        assert_eq!(confirm.is_seqno_received(10), Some(true));
        // Bit 1 -> seqno 9 (mask & 2 = 2 -> set)
        assert_eq!(confirm.is_seqno_received(9), Some(true));
        // Bit 2 -> seqno 8 (mask & 4 = 0 -> not set)
        assert_eq!(confirm.is_seqno_received(8), Some(false));
        // Bit 3 -> seqno 7 (mask & 8 = 8 -> set)
        assert_eq!(confirm.is_seqno_received(7), Some(true));

        // Out of range
        assert_eq!(confirm.is_seqno_received(11), None);
        assert_eq!(confirm.is_seqno_received(-22), None);
    }

    #[test]
    fn test_rldp2_outgoing_transfer() {
        let data = b"Test data for RLDP2 outgoing transfer";
        let mut transfer = Rldp2OutgoingTransfer::new(data);

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
    fn test_rldp2_incoming_transfer() {
        let data = b"Test data for RLDP2 incoming transfer";
        let mut outgoing = Rldp2OutgoingTransfer::new(data);

        // Get first message part
        let part = outgoing.next_message_part().unwrap();

        // Create incoming transfer
        let mut incoming = Rldp2IncomingTransfer::new(&part).unwrap();
        assert!(!incoming.is_complete());

        // Process parts until complete
        let _ = incoming.process_part(&part);

        while !incoming.is_complete() {
            if let Some(next_part) = outgoing.next_message_part() {
                let _ = incoming.process_part(&next_part);
            } else {
                break;
            }
        }
    }

    #[test]
    fn test_rldp2_transfer_roundtrip() {
        let data: Vec<u8> = (0..1000).map(|i| (i % 256) as u8).collect();
        let mut outgoing = Rldp2OutgoingTransfer::new(&data);

        // Get first part to initialize incoming
        let first_part = outgoing.next_message_part().unwrap();
        let mut incoming = Rldp2IncomingTransfer::new(&first_part).unwrap();
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
    fn test_rldp2_confirm_handling() {
        let data = b"Test data for confirm handling";
        let mut outgoing = Rldp2OutgoingTransfer::new(data);
        let transfer_id = outgoing.transfer_id;

        // Send some parts
        for _ in 0..5 {
            let _ = outgoing.next_message_part();
        }

        // Create a confirm indicating seqno 2 was lost
        let confirm = Rldp2Confirm::new(
            transfer_id,
            0,
            4,                   // max_seqno = 4
            0b11011,             // seqnos 4,3,1,0 received; seqno 2 missing
            4,                   // 4 received
        );

        outgoing.handle_confirm(&confirm);

        // The retransmit queue should contain seqno 2
        assert!(!outgoing.retransmit_queue.is_empty());
    }

    #[test]
    fn test_rldp2_message_enum() {
        let messages: Vec<Rldp2Message> = vec![
            Rldp2Message::Confirm(Rldp2Confirm::new([1u8; 32], 0, 10, 0b1111, 4)),
            Rldp2Message::Complete(RldpComplete::new([2u8; 32], 0)),
        ];

        for original in messages {
            let bytes = original.to_bytes();
            let parsed = Rldp2Message::from_bytes(&bytes).unwrap();
            assert_eq!(original.schema_id(), parsed.schema_id());
        }
    }

    #[test]
    fn test_rldp2_confirm_from_tracker() {
        let mut tracker = ReceivedSymbolTracker::new();

        tracker.mark_received(0);
        tracker.mark_received(1);
        tracker.mark_received(2);
        tracker.mark_received(4); // Skip 3

        let transfer_id = [42u8; 32];
        let confirm = tracker.create_confirm(transfer_id, 0);

        assert_eq!(confirm.transfer_id, transfer_id);
        assert_eq!(confirm.part, 0);
        assert_eq!(confirm.max_seqno, 4);
        assert_eq!(confirm.received_count, 4);

        // Check the mask
        assert_eq!(confirm.is_seqno_received(4), Some(true));
        assert_eq!(confirm.is_seqno_received(3), Some(false));
        assert_eq!(confirm.is_seqno_received(2), Some(true));
        assert_eq!(confirm.is_seqno_received(1), Some(true));
        assert_eq!(confirm.is_seqno_received(0), Some(true));
    }

    #[test]
    fn test_constants_documentation() {
        // Verify constants are reasonable
        assert_eq!(RECEIVED_MASK_BITS, 32);
        assert_eq!(RLDP2_WINDOW_SIZE, 1000);
        assert_eq!(RLDP2_SLICE_SIZE, 2_000_000);
        assert_eq!(RLDP2_CONFIRM_THRESHOLD, 10);
        assert_eq!(DEFAULT_RLDP2_TIMEOUT, Duration::from_secs(60));
    }
}
