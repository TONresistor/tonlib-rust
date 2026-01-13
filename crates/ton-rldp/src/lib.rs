//! # ton-rldp
//!
//! RLDP (Reliable Large Datagram Protocol) implementation for TON network.
//!
//! RLDP enables reliable transfer of large data over ADNL UDP using Forward
//! Error Correction (FEC) based on RaptorQ fountain codes. This allows data
//! to be recovered even with significant packet loss.
//!
//! ## Overview
//!
//! RLDP is used in TON for:
//! - Transferring blocks between validators
//! - DHT value storage/retrieval
//! - Overlay network messages
//! - Any large data transfer over unreliable UDP
//!
//! ## Protocol Flow
//!
//! ```text
//! Sender                                              Receiver
//!    |                                                    |
//!    |  Generate random transfer_id                       |
//!    |  Encode data with RaptorQ FEC                      |
//!    |                                                    |
//!    |  ────── rldp.messagePart (seqno=0) ──────────────> |
//!    |  ────── rldp.messagePart (seqno=1) ──────────────> |
//!    |  ────── rldp.messagePart (seqno=2) ──────────────> |
//!    |  ...                                               |
//!    |                      (accumulates FEC symbols)     |
//!    |                      (decodes when sufficient)     |
//!    |                                                    |
//!    |  <───────────── rldp.complete ─────────────────── |
//!    |                                                    |
//!    |  Stop sending                                      |
//! ```
//!
//! ## FEC (Forward Error Correction)
//!
//! RLDP uses RaptorQ fountain codes which have the following properties:
//!
//! - Data is encoded into N source symbols
//! - An unlimited number of repair symbols can be generated
//! - Original data can be recovered from any K symbols (where K is slightly more than N)
//! - Works with any packet loss pattern
//!
//! ## Query/Answer Pattern
//!
//! RLDP also provides a request/response pattern:
//!
//! ```text
//! Client                                              Server
//!    |                                                    |
//!    |  ──────── rldp.query (via RLDP transfer) ────────> |
//!    |                                                    |
//!    |                        (processes query)           |
//!    |                                                    |
//!    |  <─────── rldp.answer (via RLDP transfer) ──────── |
//! ```
//!
//! ## Example: FEC Encoding/Decoding
//!
//! ```rust
//! use ton_rldp::fec::{FecEncoder, FecDecoder, SYMBOL_SIZE};
//!
//! // Encode data
//! let data = b"Hello, RLDP! This is a test of forward error correction.";
//! let encoder = FecEncoder::new(data);
//!
//! // Generate symbols (source + repair)
//! let symbols = encoder.encode_all(5); // 5 extra repair symbols
//!
//! // Decode (can tolerate packet loss)
//! let mut decoder = FecDecoder::new(data.len(), SYMBOL_SIZE);
//! for (seqno, packet) in &symbols {
//!     if decoder.add_packet(packet) {
//!         break; // Decoding complete
//!     }
//! }
//!
//! let recovered = decoder.decode().unwrap();
//! assert_eq!(recovered, data);
//! ```
//!
//! ## Example: RLDP Transfer
//!
//! ```rust
//! use ton_rldp::transfer::{OutgoingTransfer, IncomingTransfer};
//!
//! // Create outgoing transfer
//! let data = b"Large data to transfer reliably";
//! let mut outgoing = OutgoingTransfer::new(data);
//!
//! // Get message parts to send
//! let parts = outgoing.initial_burst();
//!
//! // On receiver side
//! let first_part = &parts[0];
//! let mut incoming = IncomingTransfer::new(first_part).unwrap();
//!
//! // Process received parts until complete
//! for part in &parts {
//!     if incoming.process_part(part).unwrap() {
//!         // Decoding complete
//!         let received_data = incoming.take_data(0).unwrap();
//!         assert_eq!(received_data, data);
//!         break;
//!     }
//! }
//! ```
//!
//! ## Example: RLDP Query
//!
//! ```rust
//! use ton_rldp::query::{RldpQueryBuilder, create_query, create_answer, parse_answer};
//!
//! // Create a query
//! let (query, query_bytes) = create_query(
//!     b"get_block",
//!     1024 * 1024,  // max 1MB answer
//!     30000,        // 30 second timeout
//! );
//!
//! // Create an answer
//! let (answer, answer_bytes) = create_answer(
//!     query.query_id,
//!     b"block data here".to_vec(),
//! );
//!
//! // Parse received answer
//! let parsed = parse_answer(&answer_bytes).unwrap();
//! assert_eq!(parsed.query_id, query.query_id);
//! ```
//!
//! ## TL Message Types
//!
//! RLDP defines the following TL message types:
//!
//! - `rldp.messagePart` - FEC-encoded data chunk
//! - `rldp.confirm` - Acknowledgement (optional optimization)
//! - `rldp.complete` - Transfer completion signal
//! - `rldp.query` - Request message
//! - `rldp.answer` - Response message
//!
//! ## FEC Types
//!
//! - `fec.raptorQ` - RaptorQ fountain code (primary)
//! - `fec.roundRobin` - Round-robin encoding
//! - `fec.online` - Online FEC

mod error;
pub mod fec;
pub mod query;
pub mod rldp2;
pub mod transfer;
pub mod types;

// Re-export main types
pub use error::{RldpError, Result};

pub use fec::{
    FecDecoder, FecEncoder, FecEncoderIter, SLICE_SIZE, SYMBOL_SIZE, WINDOW_SIZE,
    encode_for_transfer, decode_from_symbols,
};

pub use query::{
    QueryManager, PendingQuery, RldpQueryBuilder, SharedQueryManager,
    create_answer, create_query, generate_query_id, new_shared_manager as new_query_manager,
    parse_answer, parse_query, rldp_query,
    DEFAULT_MAX_ANSWER_SIZE, DEFAULT_QUERY_TIMEOUT_MS,
};

pub use transfer::{
    IncomingTransfer, OutgoingTransfer, TransferConfig, TransferManager, TransferStats,
    SharedTransferManager, generate_transfer_id, new_shared_manager as new_transfer_manager,
    DEFAULT_BURST_SIZE, DEFAULT_INITIAL_DELAY, DEFAULT_SYMBOL_INTERVAL, DEFAULT_TRANSFER_TIMEOUT,
};

pub use types::{
    FecType, RldpAnswer, RldpComplete, RldpConfirm, RldpMessage, RldpMessagePart, RldpQuery,
    RldpTypeError,
    // Schema IDs
    FEC_ONLINE, FEC_RAPTORQ, FEC_ROUND_ROBIN,
    RLDP_ANSWER, RLDP_COMPLETE, RLDP_CONFIRM, RLDP_MESSAGE_PART, RLDP_QUERY,
};

// RLDP2 re-exports
pub use rldp2::{
    Rldp2Confirm, Rldp2IncomingTransfer, Rldp2Message, Rldp2MessagePart,
    Rldp2OutgoingTransfer, Rldp2TransferConfig, ReceivedSymbolTracker,
    // Schema IDs
    RLDP2_CONFIRM, RLDP2_MESSAGE_PART,
    // Constants
    DEFAULT_RLDP2_TIMEOUT, RECEIVED_MASK_BITS, RLDP2_CONFIRM_THRESHOLD,
    RLDP2_SLICE_SIZE, RLDP2_WINDOW_SIZE,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exports() {
        // Verify key types are accessible
        let _ = FecEncoder::new(b"test");
        let _ = FecType::raptorq(100, 768, 1);
        let _ = generate_transfer_id();
        let _ = generate_query_id();
    }

    #[test]
    fn test_constants() {
        // FEC constants
        assert_eq!(SYMBOL_SIZE, 768);
        assert_eq!(SLICE_SIZE, 2048);
        assert_eq!(WINDOW_SIZE, 1000);

        // Query constants
        assert_eq!(DEFAULT_MAX_ANSWER_SIZE, 2 * 1024 * 1024);
        assert_eq!(DEFAULT_QUERY_TIMEOUT_MS, 30000);
    }

    #[test]
    fn test_schema_ids() {
        assert_eq!(FEC_RAPTORQ, 0x19a4f8ba);
        assert_eq!(RLDP_MESSAGE_PART, 0x7d1f3f2f);
        assert_eq!(RLDP_COMPLETE, 0xb71a7818);
        assert_eq!(RLDP_QUERY, 0x3b5d0d8f);
        assert_eq!(RLDP_ANSWER, 0xa556c3cc);
    }

    #[test]
    fn test_full_transfer_roundtrip() {
        // This test simulates a complete RLDP transfer
        let data: Vec<u8> = (0..2000).map(|i| (i % 256) as u8).collect();

        // Sender side
        let mut outgoing = OutgoingTransfer::new(&data);
        let transfer_id = outgoing.transfer_id;

        // Get initial burst
        let parts = outgoing.initial_burst();

        // Receiver side
        let mut incoming = IncomingTransfer::new(&parts[0]).unwrap();

        // Process parts
        for part in &parts {
            let complete = incoming.process_part(part).unwrap_or(false);
            if complete {
                break;
            }
        }

        // If not complete, continue with more parts
        while !incoming.is_complete() {
            if let Some(part) = outgoing.next_message_part() {
                if incoming.process_part(&part).unwrap() {
                    break;
                }
            } else {
                break;
            }
        }

        // Verify data
        assert!(incoming.is_complete());
        let received = incoming.take_data(0).unwrap();
        assert_eq!(received, data);

        // Create complete message
        let complete = incoming.create_complete(0);
        assert_eq!(complete.transfer_id, transfer_id);
    }

    #[test]
    fn test_query_answer_roundtrip() {
        // Create query
        let (query, query_bytes) = create_query(b"test request", 1024, 5000);

        // Parse query
        let parsed_query = parse_query(&query_bytes).unwrap();
        assert_eq!(parsed_query.query_id, query.query_id);
        assert_eq!(parsed_query.data, b"test request");

        // Create answer
        let (_answer, answer_bytes) = create_answer(query.query_id, b"test response".to_vec());

        // Parse answer
        let parsed_answer = parse_answer(&answer_bytes).unwrap();
        assert_eq!(parsed_answer.query_id, query.query_id);
        assert_eq!(parsed_answer.data, b"test response");
    }

    #[test]
    fn test_fec_with_loss() {
        // Test FEC recovery with 30% packet loss
        let data: Vec<u8> = (0..3000).map(|i| (i % 256) as u8).collect();

        let (fec_type, symbols) = encode_for_transfer(&data, 0.5);

        // Simulate 30% loss by skipping some symbols
        let received: Vec<_> = symbols
            .into_iter()
            .enumerate()
            .filter(|(i, _)| i % 10 < 7) // Keep 70%
            .map(|(_, s)| s)
            .collect();

        // Should still be able to decode
        let recovered = decode_from_symbols(&fec_type, received).unwrap();
        assert_eq!(recovered, data);
    }

    #[test]
    fn test_transfer_manager() {
        let mut manager = TransferManager::new();

        // Start a transfer
        let data = b"manager test data";
        let (transfer_id, _rx) = manager.start_send(data);

        // Get parts
        let burst = manager.initial_burst(&transfer_id);
        assert!(!burst.is_empty());

        // Simulate complete
        let complete = RldpComplete::new(transfer_id, 0);
        manager.handle_complete(&complete);

        // Transfer should be removed
        assert_eq!(manager.stats().outgoing_count, 0);
    }

    #[test]
    fn test_query_manager() {
        let mut manager = QueryManager::new();

        // Register query
        let query = RldpQueryBuilder::new()
            .data(b"query data".to_vec())
            .timeout_ms(5000)
            .build();
        let query_id = query.query_id;

        let _rx = manager.register_query(query);
        assert_eq!(manager.pending_count(), 1);

        // Handle answer
        let answer = RldpAnswer::new(query_id, b"answer data".to_vec());
        let matched = manager.handle_answer(answer);

        assert!(matched);
        assert_eq!(manager.pending_count(), 0);
    }
}
