# tonnet-rust

[![CI](https://github.com/TONresistor/tonnet-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/TONresistor/tonnet-rs/actions/workflows/ci.yml)
[![Rust](https://img.shields.io/badge/rust-1.85%2B-orange?logo=rust)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

**Native Rust SDK for TON Blockchain.** Full protocol stack implementation with 100% conformance to [ton-blockchain/ton](https://github.com/ton-blockchain/ton).

Build wallets, dApps, payment channels, and decentralized services on The Open Network with type-safe, async-first Rust. Supports ADNL, DHT, RLDP, TON Storage, TON Sites, Jettons (TEP-74), NFTs (TEP-62), and off-chain payments.

## Crates

| Layer | Crate | Description |
|-------|-------|-------------|
| **Data** | `ton-crypto` | Ed25519, X25519, AES-CTR, SHA256 |
| | `ton-tl` | TL serialization |
| | `ton-cell` | Cell & BoC |
| **Network** | `ton-adnl` | ADNL TCP/UDP |
| | `ton-dht` | Kademlia DHT |
| | `ton-rldp` | RaptorQ FEC |
| | `ton-overlay` | Overlay networks |
| **Application** | `ton-dns` | .ton domains |
| | `ton-storage` | P2P storage |
| | `ton-sites` | HTTP/RLDP |
| | `ton-payments` | Payment channels |
| **Assets** | `ton-wallet` | V3R2, V4R2, V5R1 |
| | `ton-jetton` | TEP-74 tokens |
| | `ton-nft` | TEP-62 NFTs |

## Installation

```toml
[dependencies]
ton-crypto = { git = "https://github.com/TONresistor/tonnet-rs" }
ton-cell = { git = "https://github.com/TONresistor/tonnet-rs" }
ton-wallet = { git = "https://github.com/TONresistor/tonnet-rs" }
ton-payments = { git = "https://github.com/TONresistor/tonnet-rs" }
ton-adnl = { git = "https://github.com/TONresistor/tonnet-rs" }
```

## Usage

### Wallet & Transactions

<details>
<summary><b>Create a Wallet</b></summary>

```rust
use ton_crypto::Ed25519Keypair;
use ton_wallet::{Wallet, WalletV4R2};

let keypair = Ed25519Keypair::generate();
let wallet = WalletV4R2::new(keypair, 0)?; // workchain 0

println!("Address: {}", wallet.address());
println!("Public key: {:?}", wallet.public_key());
```
</details>

<details>
<summary><b>Generate from Mnemonic</b></summary>

```rust
use ton_wallet::{Mnemonic, WalletV4R2, Wallet};

// Generate new mnemonic
let mnemonic = Mnemonic::generate();
println!("Words: {}", mnemonic.to_phrase());

// Or restore from existing phrase
let mnemonic = Mnemonic::from_phrase("word1 word2 ... word24")?;

let keypair = mnemonic.to_keypair();
let wallet = WalletV4R2::new(keypair, 0)?;
```
</details>

<details>
<summary><b>Create Transfer Message</b></summary>

```rust
use ton_wallet::{Wallet, WalletV4R2, Transfer};
use ton_cell::MsgAddress;

let wallet = WalletV4R2::new(keypair, 0)?;
let dest = MsgAddress::from_string("0:abc123...")?;

let transfer = Transfer::new(dest, 1_000_000_000) // 1 TON in nanotons
    .with_bounce(true)
    .with_mode(3);

let seqno = 0; // Get from blockchain
let valid_until = u32::MAX;

let body = wallet.create_transfer_body(seqno, &[transfer], valid_until)?;
let signed = wallet.sign(&body)?;
let message = wallet.create_external_message(&signed)?;
```
</details>

<details>
<summary><b>Send Transaction</b></summary>

```rust
use ton_adnl::LiteClient;
use ton_cell::BagOfCells;

let client = LiteClient::connect("ip:port", &server_pubkey).await?;

// message is the Cell from create_external_message
let boc = BagOfCells::from_root(message);
let bytes = boc.serialize()?;

let status = client.send_message(&bytes).await?;
println!("Sent: {:?}", status);
```
</details>

<details>
<summary><b>Add Comment to Transfer</b></summary>

```rust
use ton_wallet::{Transfer, build_comment};
use ton_cell::MsgAddress;

let comment = build_comment("Hello from Rust!")?;

let transfer = Transfer::new(dest_address, 500_000_000) // 0.5 TON
    .with_payload(comment)
    .with_bounce(true);
```
</details>

<details>
<summary><b>Batch Transfers (Highload)</b></summary>

```rust
use ton_wallet::{HighloadV2R2, Wallet, Transfer};

let wallet = HighloadV2R2::new(keypair, 0)?;

let transfers: Vec<Transfer> = recipients
    .iter()
    .map(|(addr, amount)| Transfer::new(addr.clone(), *amount))
    .collect();

// Up to 254 transfers in one transaction
let query_id = HighloadV2R2::generate_query_id();
let body = wallet.create_batch_transfer_body(query_id, &transfers, u32::MAX)?;
let signed = wallet.sign(&body)?;
```
</details>

### Cryptography

<details>
<summary><b>Sign & Verify Message</b></summary>

```rust
use ton_crypto::{Ed25519Keypair, verify_signature};

let keypair = Ed25519Keypair::generate();
let message = b"Hello TON";

// Sign
let signature = keypair.sign(message);

// Verify with keypair
keypair.verify(message, &signature)?;

// Verify with public key only
verify_signature(&keypair.public_key, message, &signature)?;
```
</details>

<details>
<summary><b>AES Encryption</b></summary>

```rust
use ton_crypto::AesCtrCipher;

let key = [0u8; 32]; // Your 256-bit key
let iv = [0u8; 16];  // Your 128-bit IV

let mut cipher = AesCtrCipher::new(key, iv);

// Encrypt
let mut data = b"Secret message".to_vec();
cipher.encrypt_in_place(&mut data);

// Decrypt (reset cipher first)
cipher.reset();
cipher.decrypt_in_place(&mut data);
```
</details>

<details>
<summary><b>SHA256 Hashing</b></summary>

```rust
use ton_crypto::{sha256, Sha256Hasher};

// Simple hash
let hash = sha256(b"Hello TON");

// Streaming hash
let mut hasher = Sha256Hasher::new();
hasher.update(b"Hello ");
hasher.update(b"TON");
let hash = hasher.finalize();
```
</details>

<details>
<summary><b>ECDH Key Exchange</b></summary>

```rust
use ton_crypto::X25519Keypair;

let alice = X25519Keypair::generate();
let bob = X25519Keypair::generate();

// Both derive the same shared secret
let shared_alice = alice.ecdh(&bob.public_key)?;
let shared_bob = bob.ecdh(&alice.public_key)?;

assert_eq!(shared_alice, shared_bob);
```
</details>

### Cells & Data

<details>
<summary><b>Build a Cell</b></summary>

```rust
use ton_cell::CellBuilder;
use std::sync::Arc;

let mut builder = CellBuilder::new();
builder.store_u32(0xDEADBEEF)?;
builder.store_u64(1234567890)?;
builder.store_bytes(&[1, 2, 3, 4])?;
builder.store_coins(1_000_000_000)?; // 1 TON

// Add child reference
let child = CellBuilder::new().build()?;
builder.store_ref(Arc::new(child))?;

let cell = builder.build()?;
```
</details>

<details>
<summary><b>Read a Cell</b></summary>

```rust
use ton_cell::CellSlice;

let mut slice = CellSlice::new(&cell);

let value = slice.load_u32()?;
let amount = slice.load_coins()?;
let bytes = slice.load_bytes(4)?;

// Load child reference
let child = slice.load_ref()?;
```
</details>

<details>
<summary><b>Serialize to BoC</b></summary>

```rust
use ton_cell::BagOfCells;

// Serialize
let boc = BagOfCells::from_root(cell);
let bytes = boc.serialize()?;
let base64 = boc.serialize_to_base64()?;

// Deserialize
let boc = BagOfCells::deserialize(&bytes)?;
let root = boc.single_root()?;

// From base64
let boc = BagOfCells::deserialize_from_base64(&base64_string)?;
```
</details>

<details>
<summary><b>Parse Address</b></summary>

```rust
use ton_cell::MsgAddress;

// From raw format
let addr = MsgAddress::from_string("0:abc123...")?;

// From user-friendly format
let addr = MsgAddress::from_string("EQDtFpEwcFAEcRe...")?;

// Convert formats
let raw = addr.to_raw_string();
let friendly = addr.to_user_friendly(true, false); // bounceable, mainnet
```
</details>

### Payment Channels (Off-chain)

<details>
<summary><b>Create Payment Channel</b></summary>

```rust
use ton_crypto::Ed25519Keypair;
use ton_payments::PaymentChannel;

let alice = Ed25519Keypair::generate();
let bob = Ed25519Keypair::generate();

let channel_id = PaymentChannel::generate_channel_id();
let mut channel = PaymentChannel::new(
    channel_id,
    alice.public_key,
    bob.public_key,
    1_000_000_000,  // Alice's deposit: 1 TON
    1_000_000_000,  // Bob's deposit: 1 TON
    Some(alice),    // Our keypair (we are Alice)
    true,           // We are party A
);

channel.initialize()?;
```
</details>

<details>
<summary><b>Make Off-chain Payment</b></summary>

```rust
// Alice pays Bob 0.1 TON instantly (no blockchain tx needed)
let signed_state = channel.make_payment(100_000_000)?;

// Send signed_state to Bob via P2P
// Bob verifies and updates his state
bob_channel.receive_payment(&signed_state)?;

println!("Alice balance: {}", channel.balance_a());
println!("Bob balance: {}", channel.balance_b());
```
</details>

<details>
<summary><b>Conditional Payment (HTLC)</b></summary>

```rust
use ton_payments::{PaymentChannel, ConditionalPayment};

// Create hash-locked payment
let preimage = ton_payments::generate_preimage();
let hash = ton_payments::hash_preimage(&preimage);

let conditional = ConditionalPayment::htlc(
    100_000_000,  // 0.1 TON
    hash,
    deadline,     // Unix timestamp
);

channel.make_conditional_payment(conditional)?;

// Receiver reveals preimage to claim
channel.settle_conditional(&preimage)?;
```
</details>

<details>
<summary><b>Close Channel Cooperatively</b></summary>

```rust
// Both parties sign final state
let alice_sig = alice_channel.sign_for_close()?;
let bob_sig = bob_channel.sign_for_close()?;

// Create cooperative close
let close_state = channel.cooperative_close(alice_sig, bob_sig)?;

// Submit to blockchain to withdraw funds
```
</details>

### Network (ADNL)

<details>
<summary><b>Connect to Liteserver</b></summary>

```rust
use ton_adnl::LiteClient;

// Server pubkey from global config
let pubkey: [u8; 32] = hex::decode("...")?.try_into()?;

let client = LiteClient::connect("1.2.3.4", 12345, &pubkey).await?;

// Keep connection alive
client.ping().await?;
```
</details>

<details>
<summary><b>Get Account Balance</b></summary>

```rust
use ton_adnl::LiteClient;
use ton_cell::MsgAddress;

let client = LiteClient::connect(host, port, &pubkey).await?;

let addr = MsgAddress::from_string("0:abc123...")?;
let state = client.get_account_state_latest(&addr).await?;

println!("Balance: {} nanoTON", state.balance);
println!("State: {:?}", state.state);
```
</details>

<details>
<summary><b>Get Transactions</b></summary>

```rust
let addr = MsgAddress::from_string("0:abc123...")?;

// Get last 10 transactions
let txs = client.get_transactions(
    &addr,
    10,           // count
    last_lt,      // logical time
    &last_hash,   // transaction hash
).await?;

for tx in txs.transactions {
    println!("TX: lt={}, hash={:?}", tx.lt, tx.hash);
}
```
</details>

### Storage (P2P Files)

<details>
<summary><b>Create a Bag from Data</b></summary>

```rust
use ton_storage::{
    TorrentInfo, TorrentHeader, Bag,
    build_merkle_tree, split_into_chunks,
};

let data = b"Hello, TON Storage!";

// Build Merkle tree for verification
let tree = build_merkle_tree(data, 128 * 1024)?; // 128KB chunks
let root_hash = tree.root_hash();

// Create torrent header and info
let header = TorrentHeader::single_file("hello.txt", data.len() as u64);
let info = TorrentInfo::new(
    data.len() as u64,
    root_hash,
    0,
    header.calculate_hash(),
);

// Calculate BagID (content hash)
let bag_id = info.calculate_bag_id();
let bag = Bag::new(info, header);

println!("BagID: {:?}", bag_id);
```
</details>

<details>
<summary><b>Verify Chunks with Merkle Proofs</b></summary>

```rust
use ton_storage::{
    build_merkle_tree, split_into_chunks,
    verify_chunk_with_proof,
};

let data = b"Data to verify with Merkle proofs";
let chunk_size = 16;

// Build tree and split data
let tree = build_merkle_tree(data, chunk_size)?;
let chunks = split_into_chunks(data, chunk_size)?;

// Verify each chunk
for chunk in &chunks {
    let proof = tree.generate_proof(chunk.index)?;

    // Verify against root hash
    assert!(verify_chunk_with_proof(
        &tree.root_hash(),
        &chunk.data,
        &proof
    ));
}
```
</details>

<details>
<summary><b>Download a Bag (Network)</b></summary>

```rust
use ton_storage::{StorageClient, StorageClientConfig};

// Create client with DHT, Overlay, and RLDP
let client = StorageClient::new(dht, overlay, rldp);

// Find peers for a bag
let bag_id: [u8; 32] = /* ... */;
let peers = client.find_peers(&bag_id).await?;

// Download the bag
let downloaded = client.download_bag(&bag_id).await?;

// Extract a specific file
let readme = downloaded.extract_file("readme.txt")?;
println!("File content: {} bytes", readme.len());
```
</details>

### TON Sites (HTTP over RLDP)

<details>
<summary><b>Fetch a .ton Site</b></summary>

```rust
use ton_sites::{TonSiteClient, parse_ton_url};

// Parse TON URL
let url = parse_ton_url("http://example.ton/index.html")?;
println!("Domain: {}", url.domain);  // example.ton
println!("Path: {}", url.path);      // /index.html

// Create client (with DNS resolver and RLDP transport)
let client = TonSiteClient::new(dns_resolver, rldp_transport);

// GET request
let response = client.get("http://example.ton/api/data").await?;

if response.is_success() {
    println!("Body: {}", response.body_string()?);
}
```
</details>

<details>
<summary><b>HTTP POST Request</b></summary>

```rust
use ton_sites::{TonSiteClient, HttpRequest};

let client = TonSiteClient::new(dns_resolver, rldp_transport);

// Build POST request with JSON body
let request = HttpRequest::post("/api/submit")
    .with_host("myapp.ton")
    .with_header("Content-Type", "application/json");

let body = r#"{"action": "submit", "data": [1, 2, 3]}"#;
let response = client.request(request, body.as_bytes()).await?;

println!("Status: {}", response.status_code());
```
</details>

<details>
<summary><b>Direct ADNL Access</b></summary>

```rust
use ton_sites::{TonSiteClient, format_adnl_address};

// Access site directly via ADNL address (no DNS)
let adnl_addr: [u8; 32] = /* server's ADNL address */;
let adnl_hex = format_adnl_address(&adnl_addr);

// URL format: http://<64-hex-chars>.adnl/path
let url = format!("http://{}.adnl/api/status", adnl_hex);

let response = client.get(&url).await?;
```
</details>

## Build

```bash
git clone https://github.com/TONresistor/tonnet-rs
cd tonnet-rs
cargo build --workspace
cargo test --workspace
```

## License

MIT
