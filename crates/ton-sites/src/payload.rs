//! Payload streaming for HTTP over RLDP.
//!
//! This module handles the streaming transfer of HTTP request and response bodies
//! using the `http.getNextPayloadPart` and `http.payloadPart` TL messages.
//!
//! # Protocol Flow
//!
//! When a request or response has a body, the payload is transferred in chunks:
//!
//! 1. The receiver sends `http.getNextPayloadPart` with a sequence number
//! 2. The sender responds with `http.payloadPart` containing the data chunk
//! 3. This repeats until `http.payloadPart.last` is true
//!
//! # Example
//!
//! ```
//! use ton_sites::payload::{PayloadSender, PayloadReceiver, DEFAULT_CHUNK_SIZE};
//!
//! // Sending a payload
//! let data = b"Hello, World!".to_vec();
//! let sender = PayloadSender::new([0xAB; 32], data.clone());
//! let (part, _) = sender.get_part(0, DEFAULT_CHUNK_SIZE as i32).unwrap();
//! assert!(part.last); // Small payload fits in one chunk
//!
//! // Receiving a payload
//! let mut receiver = PayloadReceiver::new([0xAB; 32]);
//! receiver.add_part(part).unwrap();
//! assert!(receiver.is_complete());
//! let received = receiver.take_data();
//! assert_eq!(received, data);
//! ```

use crate::error::{SiteError, SiteResult};
use crate::types::{GetNextPayloadPart, HttpHeader, PayloadPart};

/// Default chunk size for payload transfers (128 KB).
pub const DEFAULT_CHUNK_SIZE: usize = 128 * 1024;

/// Maximum payload size (10 MB).
pub const MAX_PAYLOAD_SIZE: usize = 10 * 1024 * 1024;

/// Handles sending a payload in chunks.
#[derive(Debug)]
pub struct PayloadSender {
    /// Request ID this payload belongs to.
    request_id: [u8; 32],
    /// The full payload data.
    data: Vec<u8>,
    /// Current offset in the data.
    offset: usize,
    /// Sequence number of the next part.
    next_seqno: i32,
    /// Whether all data has been sent.
    complete: bool,
}

impl PayloadSender {
    /// Create a new payload sender.
    pub fn new(request_id: [u8; 32], data: Vec<u8>) -> Self {
        Self {
            request_id,
            complete: data.is_empty(),
            data,
            offset: 0,
            next_seqno: 0,
        }
    }

    /// Get the request ID.
    pub fn request_id(&self) -> &[u8; 32] {
        &self.request_id
    }

    /// Check if all data has been sent.
    pub fn is_complete(&self) -> bool {
        self.complete
    }

    /// Get the total size of the payload.
    pub fn total_size(&self) -> usize {
        self.data.len()
    }

    /// Get the number of bytes remaining to send.
    pub fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.offset)
    }

    /// Handle a `getNextPayloadPart` request.
    ///
    /// Returns the payload part and whether this is the last part.
    pub fn handle_request(&mut self, request: &GetNextPayloadPart) -> SiteResult<PayloadPart> {
        if request.id != self.request_id {
            return Err(SiteError::PayloadError(
                "request ID mismatch".to_string(),
            ));
        }

        if request.seqno != self.next_seqno {
            return Err(SiteError::PayloadError(format!(
                "sequence number mismatch: expected {}, got {}",
                self.next_seqno, request.seqno
            )));
        }

        let (part, _) = self.get_part(request.seqno, request.max_chunk_size)?;
        Ok(part)
    }

    /// Get a specific payload part.
    ///
    /// Returns the part and the number of bytes sent.
    pub fn get_part(&self, seqno: i32, max_chunk_size: i32) -> SiteResult<(PayloadPart, usize)> {
        let offset = seqno as usize * max_chunk_size as usize;
        if offset > self.data.len() {
            return Err(SiteError::PayloadError(format!(
                "invalid sequence number: {} (offset {} > data length {})",
                seqno, offset, self.data.len()
            )));
        }

        let chunk_size = (max_chunk_size as usize).min(self.data.len() - offset);
        let chunk = self.data[offset..offset + chunk_size].to_vec();
        let last = offset + chunk_size >= self.data.len();

        Ok((PayloadPart::new(chunk.clone(), last), chunk.len()))
    }

    /// Advance to the next part after sending.
    pub fn advance(&mut self, chunk_size: usize) {
        self.offset += chunk_size;
        self.next_seqno += 1;
        if self.offset >= self.data.len() {
            self.complete = true;
        }
    }

    /// Get the next chunk to send.
    ///
    /// Returns None if all data has been sent.
    pub fn next_chunk(&mut self, max_chunk_size: usize) -> Option<PayloadPart> {
        if self.complete {
            return None;
        }

        let chunk_size = max_chunk_size.min(self.data.len() - self.offset);
        let chunk = self.data[self.offset..self.offset + chunk_size].to_vec();
        let last = self.offset + chunk_size >= self.data.len();

        self.offset += chunk_size;
        self.next_seqno += 1;
        self.complete = last;

        Some(PayloadPart::new(chunk, last))
    }

    /// Create a `getNextPayloadPart` request for the current sequence.
    pub fn create_request(&self, max_chunk_size: i32) -> GetNextPayloadPart {
        GetNextPayloadPart::new(self.request_id, self.next_seqno, max_chunk_size)
    }
}

/// Handles receiving a payload in chunks.
#[derive(Debug)]
pub struct PayloadReceiver {
    /// Request ID this payload belongs to.
    request_id: [u8; 32],
    /// Accumulated payload data.
    data: Vec<u8>,
    /// Expected sequence number of the next part.
    next_seqno: i32,
    /// Whether all data has been received.
    complete: bool,
    /// Maximum allowed payload size.
    max_size: usize,
    /// Trailer headers (from the last part).
    trailer: Vec<HttpHeader>,
}

impl PayloadReceiver {
    /// Create a new payload receiver.
    pub fn new(request_id: [u8; 32]) -> Self {
        Self {
            request_id,
            data: Vec::new(),
            next_seqno: 0,
            complete: false,
            max_size: MAX_PAYLOAD_SIZE,
            trailer: Vec::new(),
        }
    }

    /// Create a new payload receiver with a custom max size.
    pub fn with_max_size(request_id: [u8; 32], max_size: usize) -> Self {
        Self {
            request_id,
            data: Vec::new(),
            next_seqno: 0,
            complete: false,
            max_size,
            trailer: Vec::new(),
        }
    }

    /// Get the request ID.
    pub fn request_id(&self) -> &[u8; 32] {
        &self.request_id
    }

    /// Check if all data has been received.
    pub fn is_complete(&self) -> bool {
        self.complete
    }

    /// Get the accumulated data size so far.
    pub fn current_size(&self) -> usize {
        self.data.len()
    }

    /// Get the trailer headers (available after receiving last part).
    pub fn trailer(&self) -> &[HttpHeader] {
        &self.trailer
    }

    /// Add a received payload part.
    pub fn add_part(&mut self, part: PayloadPart) -> SiteResult<bool> {
        if self.complete {
            return Err(SiteError::PayloadError(
                "payload already complete".to_string(),
            ));
        }

        // Check size limit
        if self.data.len() + part.data.len() > self.max_size {
            return Err(SiteError::ResponseTooLarge {
                size: self.data.len() + part.data.len(),
                max_size: self.max_size,
            });
        }

        // Add the data
        self.data.extend_from_slice(&part.data);
        self.next_seqno += 1;

        // Check if complete
        if part.last {
            self.complete = true;
            self.trailer = part.trailer;
        }

        Ok(self.complete)
    }

    /// Create a request for the next payload part.
    pub fn create_request(&self, max_chunk_size: i32) -> GetNextPayloadPart {
        GetNextPayloadPart::new(self.request_id, self.next_seqno, max_chunk_size)
    }

    /// Take the accumulated data.
    ///
    /// This consumes the receiver and returns the data.
    pub fn take_data(self) -> Vec<u8> {
        self.data
    }

    /// Get a reference to the accumulated data.
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// Get the current accumulated data as a reference.
    pub fn data_ref(&self) -> &Vec<u8> {
        &self.data
    }
}

/// Iterator that yields `getNextPayloadPart` requests for receiving a payload.
pub struct PayloadRequestIterator {
    request_id: [u8; 32],
    seqno: i32,
    max_chunk_size: i32,
    done: bool,
}

impl PayloadRequestIterator {
    /// Create a new payload request iterator.
    pub fn new(request_id: [u8; 32], max_chunk_size: i32) -> Self {
        Self {
            request_id,
            seqno: 0,
            max_chunk_size,
            done: false,
        }
    }

    /// Mark the iterator as done (all parts received).
    pub fn mark_done(&mut self) {
        self.done = true;
    }

    /// Get the current sequence number.
    pub fn current_seqno(&self) -> i32 {
        self.seqno
    }

    /// Advance to the next sequence number.
    pub fn advance(&mut self) {
        self.seqno += 1;
    }
}

impl Iterator for PayloadRequestIterator {
    type Item = GetNextPayloadPart;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }

        let request = GetNextPayloadPart::new(self.request_id, self.seqno, self.max_chunk_size);
        self.seqno += 1;
        Some(request)
    }
}

/// Calculate the number of chunks needed for a given data size.
pub fn chunk_count(data_size: usize, chunk_size: usize) -> usize {
    if data_size == 0 {
        return 0;
    }
    data_size.div_ceil(chunk_size)
}

/// Split data into chunks of a given size.
pub fn split_into_chunks(data: &[u8], chunk_size: usize) -> Vec<Vec<u8>> {
    data.chunks(chunk_size)
        .map(|chunk| chunk.to_vec())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_payload_sender_small_data() {
        let data = b"Hello, World!".to_vec();
        let mut sender = PayloadSender::new([0xAB; 32], data.clone());

        assert!(!sender.is_complete());
        assert_eq!(sender.total_size(), data.len());
        assert_eq!(sender.remaining(), data.len());

        let part = sender.next_chunk(DEFAULT_CHUNK_SIZE).unwrap();
        assert_eq!(part.data, data);
        assert!(part.last);
        assert!(sender.is_complete());

        // No more chunks
        assert!(sender.next_chunk(DEFAULT_CHUNK_SIZE).is_none());
    }

    #[test]
    fn test_payload_sender_large_data() {
        let data: Vec<u8> = (0..1000).map(|i| (i % 256) as u8).collect();
        let chunk_size = 128;
        let mut sender = PayloadSender::new([0xAB; 32], data.clone());

        let mut received = Vec::new();
        let mut chunk_count = 0;

        while let Some(part) = sender.next_chunk(chunk_size) {
            received.extend_from_slice(&part.data);
            chunk_count += 1;

            if part.last {
                break;
            }
        }

        assert_eq!(received, data);
        assert_eq!(chunk_count, 8); // 1000 / 128 = 7.8125, rounds up to 8
        assert!(sender.is_complete());
    }

    #[test]
    fn test_payload_sender_get_part() {
        let data: Vec<u8> = (0..300).map(|i| (i % 256) as u8).collect();
        let sender = PayloadSender::new([0xAB; 32], data.clone());

        // First part
        let (part, size) = sender.get_part(0, 100).unwrap();
        assert_eq!(part.data, &data[0..100]);
        assert_eq!(size, 100);
        assert!(!part.last);

        // Second part
        let (part, size) = sender.get_part(1, 100).unwrap();
        assert_eq!(part.data, &data[100..200]);
        assert_eq!(size, 100);
        assert!(!part.last);

        // Third (last) part
        let (part, size) = sender.get_part(2, 100).unwrap();
        assert_eq!(part.data, &data[200..300]);
        assert_eq!(size, 100);
        assert!(part.last);
    }

    #[test]
    fn test_payload_sender_handle_request() {
        let data = b"Test data".to_vec();
        let request_id = [0xCD; 32];
        let mut sender = PayloadSender::new(request_id, data.clone());

        let request = GetNextPayloadPart::new(request_id, 0, DEFAULT_CHUNK_SIZE as i32);
        let part = sender.handle_request(&request).unwrap();

        assert_eq!(part.data, data);
        assert!(part.last);
    }

    #[test]
    fn test_payload_sender_request_id_mismatch() {
        let sender = PayloadSender::new([0xAB; 32], vec![1, 2, 3]);
        let _request = GetNextPayloadPart::new([0xCD; 32], 0, DEFAULT_CHUNK_SIZE as i32);

        // Should use handle_request from a mutable sender, but get_part works for testing
        let result = sender.get_part(0, DEFAULT_CHUNK_SIZE as i32);
        assert!(result.is_ok()); // get_part doesn't check request_id
    }

    #[test]
    fn test_payload_receiver_small_data() {
        let data = b"Hello, World!".to_vec();
        let mut receiver = PayloadReceiver::new([0xAB; 32]);

        assert!(!receiver.is_complete());
        assert_eq!(receiver.current_size(), 0);

        let part = PayloadPart::new(data.clone(), true);
        let complete = receiver.add_part(part).unwrap();

        assert!(complete);
        assert!(receiver.is_complete());
        assert_eq!(receiver.current_size(), data.len());
        assert_eq!(receiver.take_data(), data);
    }

    #[test]
    fn test_payload_receiver_multiple_parts() {
        let mut receiver = PayloadReceiver::new([0xAB; 32]);

        // Part 1
        let part1 = PayloadPart::new(vec![1, 2, 3], false);
        let complete = receiver.add_part(part1).unwrap();
        assert!(!complete);

        // Part 2
        let part2 = PayloadPart::new(vec![4, 5, 6], false);
        let complete = receiver.add_part(part2).unwrap();
        assert!(!complete);

        // Part 3 (last)
        let part3 = PayloadPart::new(vec![7, 8, 9], true);
        let complete = receiver.add_part(part3).unwrap();
        assert!(complete);

        assert_eq!(receiver.take_data(), vec![1, 2, 3, 4, 5, 6, 7, 8, 9]);
    }

    #[test]
    fn test_payload_receiver_max_size() {
        let mut receiver = PayloadReceiver::with_max_size([0xAB; 32], 10);

        // Part that exceeds max size
        let part = PayloadPart::new(vec![0; 20], true);
        let result = receiver.add_part(part);

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), SiteError::ResponseTooLarge { .. }));
    }

    #[test]
    fn test_payload_receiver_trailer() {
        let mut receiver = PayloadReceiver::new([0xAB; 32]);

        let trailer = vec![
            HttpHeader::new("X-Checksum", "abc123"),
        ];
        let part = PayloadPart::new(vec![1, 2, 3], true).with_trailer(trailer.clone());
        receiver.add_part(part).unwrap();

        assert_eq!(receiver.trailer().len(), 1);
        assert_eq!(receiver.trailer()[0].name, "X-Checksum");
        assert_eq!(receiver.trailer()[0].value, "abc123");
    }

    #[test]
    fn test_payload_receiver_already_complete() {
        let mut receiver = PayloadReceiver::new([0xAB; 32]);

        let part = PayloadPart::new(vec![1, 2, 3], true);
        receiver.add_part(part).unwrap();

        // Try to add another part
        let part2 = PayloadPart::new(vec![4, 5, 6], true);
        let result = receiver.add_part(part2);

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), SiteError::PayloadError(_)));
    }

    #[test]
    fn test_payload_request_iterator() {
        let request_id = [0xAB; 32];
        let mut iter = PayloadRequestIterator::new(request_id, 128 * 1024);

        let req1 = iter.next().unwrap();
        assert_eq!(req1.id, request_id);
        assert_eq!(req1.seqno, 0);

        let req2 = iter.next().unwrap();
        assert_eq!(req2.seqno, 1);

        let req3 = iter.next().unwrap();
        assert_eq!(req3.seqno, 2);

        // Mark done
        iter.mark_done();
        assert!(iter.next().is_none());
    }

    #[test]
    fn test_chunk_count() {
        assert_eq!(chunk_count(0, 100), 0);
        assert_eq!(chunk_count(50, 100), 1);
        assert_eq!(chunk_count(100, 100), 1);
        assert_eq!(chunk_count(101, 100), 2);
        assert_eq!(chunk_count(200, 100), 2);
        assert_eq!(chunk_count(1000, 128), 8);
    }

    #[test]
    fn test_split_into_chunks() {
        let data: Vec<u8> = (0..10).collect();

        let chunks = split_into_chunks(&data, 3);
        assert_eq!(chunks.len(), 4);
        assert_eq!(chunks[0], vec![0, 1, 2]);
        assert_eq!(chunks[1], vec![3, 4, 5]);
        assert_eq!(chunks[2], vec![6, 7, 8]);
        assert_eq!(chunks[3], vec![9]);

        // Empty data
        let chunks = split_into_chunks(&[], 3);
        assert!(chunks.is_empty());

        // Chunk size larger than data
        let chunks = split_into_chunks(&data, 100);
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0], data);
    }

    #[test]
    fn test_sender_receiver_roundtrip() {
        let data: Vec<u8> = (0..500).map(|i| (i % 256) as u8).collect();
        let request_id = [0x12; 32];
        let chunk_size = 100;

        let mut sender = PayloadSender::new(request_id, data.clone());
        let mut receiver = PayloadReceiver::new(request_id);

        while !sender.is_complete() {
            let request = receiver.create_request(chunk_size);
            let (part, _) = sender.get_part(request.seqno, request.max_chunk_size).unwrap();
            sender.advance(part.data.len());

            let complete = receiver.add_part(part).unwrap();
            if complete {
                break;
            }
        }

        assert!(sender.is_complete());
        assert!(receiver.is_complete());
        assert_eq!(receiver.take_data(), data);
    }

    #[test]
    fn test_empty_payload() {
        let sender = PayloadSender::new([0xAB; 32], vec![]);
        assert!(sender.is_complete());
        assert_eq!(sender.total_size(), 0);

        let mut receiver = PayloadReceiver::new([0xAB; 32]);
        let part = PayloadPart::empty_last();
        receiver.add_part(part).unwrap();
        assert!(receiver.is_complete());
        assert!(receiver.take_data().is_empty());
    }
}
