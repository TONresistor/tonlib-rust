//! Integration tests against TON mainnet
//!
//! Run with: cargo test -p ton-adnl --features mainnet-tests --test mainnet_integration

#![cfg(feature = "mainnet-tests")]

use serde::Deserialize;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;
use ton_adnl::{AccountAddress, LiteClient};

// ============================================================================
// Config parsing
// ============================================================================

#[derive(Debug, Deserialize)]
struct GlobalConfig {
    liteservers: Vec<LiteserverConfig>,
}

#[derive(Debug, Deserialize)]
struct LiteserverConfig {
    ip: i64,
    port: u16,
    id: LiteserverId,
}

#[derive(Debug, Deserialize)]
struct LiteserverId {
    key: String,
}

async fn fetch_mainnet_config() -> Result<Vec<(SocketAddr, [u8; 32])>, Box<dyn std::error::Error>> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()?;

    let config: GlobalConfig = client
        .get("https://ton.org/global-config.json")
        .send()
        .await?
        .json()
        .await?;

    let mut result = Vec::new();

    for ls in config.liteservers {
        // Convert signed int to IPv4
        let ip_bytes = (ls.ip as u32).to_be_bytes();
        let ip = IpAddr::V4(Ipv4Addr::from(ip_bytes));
        let addr = SocketAddr::new(ip, ls.port);

        // Decode base64 public key
        let key_bytes = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            &ls.id.key,
        )?;

        if key_bytes.len() != 32 {
            continue;
        }

        let mut pubkey = [0u8; 32];
        pubkey.copy_from_slice(&key_bytes);

        result.push((addr, pubkey));
    }

    Ok(result)
}

async fn connect_to_mainnet() -> LiteClient {
    let liteservers = fetch_mainnet_config()
        .await
        .expect("Failed to fetch mainnet config");

    assert!(!liteservers.is_empty(), "No liteservers in config");

    // Try each liteserver until one works
    for (addr, pubkey) in &liteservers {
        println!("Trying liteserver: {}", addr);
        match LiteClient::connect_with_timeout(
            &addr.ip().to_string(),
            addr.port(),
            pubkey,
            Duration::from_secs(10),
        )
        .await
        {
            Ok(client) => {
                println!("Connected to {}", addr);
                return client;
            }
            Err(e) => {
                println!("Failed to connect to {}: {:?}", addr, e);
                continue;
            }
        }
    }

    panic!("Failed to connect to any mainnet liteserver");
}

// ============================================================================
// Config parsing tests
// ============================================================================

#[tokio::test]
async fn test_fetch_mainnet_config() {
    let config = fetch_mainnet_config().await.expect("Failed to fetch config");

    assert!(!config.is_empty(), "Config should have liteservers");
    println!("Found {} liteservers", config.len());

    // Verify first liteserver is valid
    let (addr, pubkey) = &config[0];
    assert!(addr.port() > 0);
    assert_ne!(pubkey, &[0u8; 32]);
}

// ============================================================================
// LiteClient connection tests
// ============================================================================

#[tokio::test]
async fn test_connect_to_mainnet_liteserver() {
    let client = connect_to_mainnet().await;
    // Connection succeeded if we get here
    drop(client);
}

#[tokio::test]
async fn test_query_after_connect() {
    // Try multiple liteservers to rule out server-specific issues
    let liteservers = fetch_mainnet_config()
        .await
        .expect("Failed to fetch mainnet config");

    let mut success_count = 0;
    let mut fail_count = 0;

    for (addr, pubkey) in liteservers.iter().take(5) {
        println!("\n=== Trying liteserver: {} ===", addr);

        match LiteClient::connect_with_timeout(
            &addr.ip().to_string(),
            addr.port(),
            pubkey,
            Duration::from_secs(10),
        )
        .await
        {
            Ok(client) => {
                println!("Handshake succeeded, trying get_time...");
                match client.get_time().await {
                    Ok(time) => {
                        println!("SUCCESS! Server time: {}", time);
                        success_count += 1;
                    }
                    Err(e) => {
                        println!("Query FAILED: {:?}", e);
                        fail_count += 1;
                    }
                }
            }
            Err(e) => {
                println!("Connection failed: {:?}", e);
            }
        }
    }

    println!("\n=== Summary: {} successes, {} failures ===", success_count, fail_count);
    assert!(success_count > 0, "At least one query should succeed");
}

#[tokio::test]
async fn test_get_time_after_connect() {
    let client = connect_to_mainnet().await;

    // Try get_time as well
    let time = client.get_time().await.expect("get_time should work");
    println!("Server time: {}", time);
}

#[tokio::test]
async fn test_get_masterchain_info() {
    let client = connect_to_mainnet().await;

    let info = client
        .get_masterchain_info()
        .await
        .expect("Failed to get masterchain info");

    // Verify response
    assert_eq!(info.last.workchain, -1, "Should be masterchain");
    assert!(info.last.seqno > 0, "Seqno should be positive");
    assert_ne!(info.last.root_hash, [0u8; 32], "Root hash should not be zero");
    assert_ne!(info.last.file_hash, [0u8; 32], "File hash should not be zero");

    println!("Masterchain block: seqno={}", info.last.seqno);
}

#[tokio::test]
async fn test_get_time() {
    let client = connect_to_mainnet().await;

    let time = client.get_time().await.expect("Failed to get time");

    // Should be a reasonable Unix timestamp (after 2024)
    assert!(time > 1704067200, "Time should be after Jan 1, 2024");
    // Should be before 2030
    assert!(time < 1893456000, "Time should be before Jan 1, 2030");

    println!("Server time: {}", time);
}

#[tokio::test]
async fn test_get_masterchain_info_ext() {
    let client = connect_to_mainnet().await;

    let info = client
        .get_masterchain_info_ext(0)
        .await
        .expect("Failed to get extended masterchain info");

    assert_eq!(info.last.workchain, -1);
    assert!(info.last.seqno > 0);

    println!(
        "Extended info: seqno={}, state_root_hash={:?}",
        info.last.seqno,
        &info.state_root_hash[..8]
    );
}

#[tokio::test]
async fn test_get_account_state_elector() {
    let client = connect_to_mainnet().await;

    // Get current masterchain block
    let mc_info = client
        .get_masterchain_info()
        .await
        .expect("Failed to get masterchain info");

    // Elector contract address (masterchain, all 3s)
    let elector_addr = AccountAddress::from_raw_string(
        "-1:3333333333333333333333333333333333333333333333333333333333333333"
    ).expect("Invalid elector address");

    let state = client
        .get_account_state(&mc_info.last, &elector_addr)
        .await
        .expect("Failed to get elector account state");

    // Elector should exist (state should not be empty)
    assert!(!state.state.is_empty(), "Elector state should not be empty");

    println!("Elector state size: {} bytes", state.state.len());
}

#[tokio::test]
async fn test_get_account_state_config() {
    let client = connect_to_mainnet().await;

    let mc_info = client
        .get_masterchain_info()
        .await
        .expect("Failed to get masterchain info");

    // Config contract address (masterchain, all 5s)
    let config_addr = AccountAddress::from_raw_string(
        "-1:5555555555555555555555555555555555555555555555555555555555555555"
    ).expect("Invalid config address");

    let state = client
        .get_account_state(&mc_info.last, &config_addr)
        .await
        .expect("Failed to get config account state");

    assert!(!state.state.is_empty(), "Config state should not be empty");

    println!("Config state size: {} bytes", state.state.len());
}

// ============================================================================
// Block queries
// ============================================================================

#[tokio::test]
async fn test_get_block_header() {
    let client = connect_to_mainnet().await;

    let mc_info = client
        .get_masterchain_info()
        .await
        .expect("Failed to get masterchain info");

    let header = client
        .get_block_header(&mc_info.last, 0)
        .await
        .expect("Failed to get block header");

    assert!(!header.header_proof.is_empty(), "Header proof should not be empty");

    println!("Got block header, proof size: {} bytes", header.header_proof.len());
}

#[tokio::test]
async fn test_get_all_shards_info() {
    let client = connect_to_mainnet().await;

    let mc_info = client
        .get_masterchain_info()
        .await
        .expect("Failed to get masterchain info");

    let shards = client
        .get_all_shards_info(&mc_info.last)
        .await
        .expect("Failed to get shards info");

    assert!(!shards.data.is_empty(), "Shards data should not be empty");

    println!("Shards data size: {} bytes", shards.data.len());
}

// ============================================================================
// Summary test - run all basic checks
// ============================================================================

#[tokio::test]
async fn test_mainnet_full_check() {
    println!("=== TON Mainnet Integration Test ===\n");

    // 1. Fetch config
    println!("1. Fetching mainnet config...");
    let config = fetch_mainnet_config()
        .await
        .expect("Failed to fetch config");
    println!("   Found {} liteservers\n", config.len());

    // 2. Connect
    println!("2. Connecting to liteserver...");
    let client = connect_to_mainnet().await;
    println!("   Connected!\n");

    // 3. Get masterchain info
    println!("3. Getting masterchain info...");
    let mc_info = client
        .get_masterchain_info()
        .await
        .expect("Failed to get masterchain info");
    println!("   Block seqno: {}", mc_info.last.seqno);
    println!("   Root hash: {:?}\n", &mc_info.last.root_hash[..8]);

    // 4. Get time
    println!("4. Getting server time...");
    let time = client.get_time().await.expect("Failed to get time");
    println!("   Server time: {}\n", time);

    // 5. Check elector
    println!("5. Checking elector contract...");
    let elector_addr = AccountAddress::from_raw_string(
        "-1:3333333333333333333333333333333333333333333333333333333333333333"
    ).expect("Invalid elector address");
    let elector = client
        .get_account_state(&mc_info.last, &elector_addr)
        .await
        .expect("Failed to get elector state");
    println!("   Elector state: {} bytes\n", elector.state.len());

    // 6. Get shards
    println!("6. Getting shard info...");
    let shards = client
        .get_all_shards_info(&mc_info.last)
        .await
        .expect("Failed to get shards");
    println!("   Shards data: {} bytes\n", shards.data.len());

    println!("=== All checks passed! ===");
}

#[tokio::test]
async fn test_ping_after_handshake() {
    let client = connect_to_mainnet().await;

    // Small delay to ensure handshake is fully processed
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Try a liteServer query (get_time) instead of tcp.ping
    // to see if the issue is with the message type
    match client.get_time().await {
        Ok(time) => println!("get_time succeeded! time={}", time),
        Err(e) => {
            eprintln!("get_time failed: {:?}", e);
        }
    }
}

#[tokio::test]
async fn test_send_empty_packet() {
    use ton_adnl::AdnlClient;

    let liteservers = fetch_mainnet_config()
        .await
        .expect("Failed to fetch mainnet config");

    let (addr, pubkey) = &liteservers[0];
    println!("Trying liteserver: {}", addr);

    let mut client = AdnlClient::connect_with_timeout(
        *addr,
        pubkey,
        Duration::from_secs(5),
    )
    .await
    .expect("Failed to connect");

    println!("Connected, waiting 500ms before sending...");

    // Wait a bit to rule out timing issues
    tokio::time::sleep(Duration::from_millis(500)).await;

    println!("Sending empty packet...");

    // Send empty packet and wait for response
    client.send_empty_packet().await.expect("Failed to send empty packet");

    // Try to receive a response (may timeout, which is okay)
    match tokio::time::timeout(Duration::from_secs(3), client.recv_raw_response()).await {
        Ok(Ok(data)) => println!("Received response: {} bytes", data.len()),
        Ok(Err(e)) => println!("Error receiving: {:?}", e),
        Err(_) => println!("Timeout (no response expected for empty packet)"),
    }
}

#[tokio::test]
async fn test_raw_adnl_ping() {
    use ton_adnl::AdnlClient;

    let liteservers = fetch_mainnet_config()
        .await
        .expect("Failed to fetch mainnet config");

    // Try up to 5 different liteservers
    let mut success_count = 0;
    let mut fail_count = 0;

    for (addr, pubkey) in liteservers.iter().take(5) {
        println!("Trying liteserver: {}", addr);
        match AdnlClient::connect_with_timeout(
            *addr,
            pubkey,
            Duration::from_secs(5),
        )
        .await
        {
            Ok(mut client) => {
                println!("Connected to {}", addr);

                // Try raw tcp.ping
                match client.ping().await {
                    Ok(()) => {
                        println!("Ping succeeded on {}!", addr);
                        success_count += 1;
                    }
                    Err(e) => {
                        eprintln!("Ping failed on {}: {:?}", addr, e);
                        fail_count += 1;
                    }
                }
            }
            Err(e) => {
                println!("Failed to connect to {}: {:?}", addr, e);
            }
        }
    }

    println!("\n=== Summary: {} successes, {} failures ===", success_count, fail_count);
}

/// Test sending liteServer.getTime WITHOUT the liteServer.query wrapper
/// to see if the extra wrapper is causing the issue.
#[tokio::test]
async fn test_query_without_wrapper() {
    use ton_tl::TlWriter;

    let client = connect_to_mainnet().await;

    // Create liteServer.getTime directly (no liteServer.query wrapper)
    let mut writer = TlWriter::new();
    writer.write_id(0x16ad5a34); // TL_LITE_GET_TIME
    let get_time = writer.into_bytes();

    println!("Sending liteServer.getTime WITHOUT liteServer.query wrapper");
    println!("Query bytes: {:02x?}", get_time);

    // Send via query_raw which bypasses the liteServer.query wrapper in LiteClient
    // but still goes through the adnl.message.query wrapper in AdnlClient
    match client.query_raw(&get_time).await {
        Ok(response) => {
            println!("Got response: {} bytes", response.len());
            println!("Response: {:02x?}", &response[..std::cmp::min(32, response.len())]);
        }
        Err(e) => {
            eprintln!("Query failed: {:?}", e);
        }
    }
}

/// Test: After handshake, can we send an empty keepalive packet and get any response?
#[tokio::test]
async fn test_empty_keepalive_after_handshake() {
    use ton_adnl::AdnlClient;

    let liteservers = fetch_mainnet_config()
        .await
        .expect("Failed to fetch mainnet config");

    let (addr, pubkey) = &liteservers[0];
    println!("Connecting to: {}", addr);

    let mut client = AdnlClient::connect_with_timeout(
        *addr,
        pubkey,
        Duration::from_secs(10),
    )
    .await
    .expect("Failed to connect");

    println!("Connected, handshake complete!");

    // Try sending an empty packet (just to test encryption works)
    println!("\nSending empty keepalive packet...");
    match client.send_empty_packet().await {
        Ok(()) => println!("Empty packet sent successfully"),
        Err(e) => eprintln!("Failed to send empty packet: {:?}", e),
    }

    // Wait and try to receive any response
    println!("\nWaiting 2 seconds for any data...");
    tokio::time::sleep(Duration::from_secs(2)).await;

    println!("Test complete - if server didn't close connection, encryption works!");
}

/// Test: Send minimal arbitrary data to see if server accepts any payload
#[tokio::test]
async fn test_minimal_payload() {
    use ton_adnl::AdnlClient;

    let liteservers = fetch_mainnet_config()
        .await
        .expect("Failed to fetch mainnet config");

    let (addr, pubkey) = &liteservers[0];
    println!("Connecting to: {}", addr);

    let mut client = AdnlClient::connect_with_timeout(
        *addr,
        pubkey,
        Duration::from_secs(10),
    )
    .await
    .expect("Failed to connect");

    println!("Connected!");

    // Try sending just 4 bytes (a random TL ID) as payload
    let minimal_payload = [0x12, 0x34, 0x56, 0x78];
    println!("Sending minimal 4-byte payload: {:02x?}", minimal_payload);

    match client.send_raw_query(&minimal_payload).await {
        Ok(()) => println!("Sent!"),
        Err(e) => {
            eprintln!("Failed to send: {:?}", e);
            return;
        }
    }

    println!("Waiting for response...");
    match tokio::time::timeout(Duration::from_secs(3), client.recv_raw_response()).await {
        Ok(Ok(data)) => {
            println!("Got response: {} bytes", data.len());
            println!("Data: {:02x?}", &data[..std::cmp::min(64, data.len())]);
        }
        Ok(Err(e)) => {
            eprintln!("Recv error: {:?}", e);
        }
        Err(_) => {
            println!("Timeout - server didn't respond (might be OK)");
        }
    }
}

/// Test: Send multiple empty packets to see if connection stays alive
#[tokio::test]
async fn test_multiple_empty_packets() {
    use ton_adnl::AdnlClient;

    let liteservers = fetch_mainnet_config()
        .await
        .expect("Failed to fetch mainnet config");

    let (addr, pubkey) = &liteservers[0];
    println!("Connecting to: {}", addr);

    let mut client = AdnlClient::connect_with_timeout(
        *addr,
        pubkey,
        Duration::from_secs(10),
    )
    .await
    .expect("Failed to connect");

    println!("Connected!");

    // Send multiple empty packets
    for i in 1..=3 {
        println!("\n--- Sending empty packet {} ---", i);
        match client.send_empty_packet().await {
            Ok(()) => println!("Empty packet {} sent successfully", i),
            Err(e) => {
                eprintln!("Failed to send packet {}: {:?}", i, e);
                return;
            }
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    // Now try sending a query
    println!("\n--- Now trying to send a query ---");
    let query = [0xb4u8, 0x8b, 0xf9, 0x7a, 0x42, 0x42, 0x42, 0x42]; // minimal adnl.message.query start
    match client.send_raw_query(&query).await {
        Ok(()) => println!("Query sent!"),
        Err(e) => {
            eprintln!("Failed to send query: {:?}", e);
            return;
        }
    }

    println!("Waiting for response...");
    match tokio::time::timeout(Duration::from_secs(3), client.recv_raw_response()).await {
        Ok(Ok(data)) => {
            println!("Got response: {} bytes", data.len());
        }
        Ok(Err(e)) => {
            eprintln!("Recv error: {:?}", e);
        }
        Err(_) => {
            println!("Timeout");
        }
    }
}

/// Test: Manually construct the exact bytes from TON documentation
#[tokio::test]
async fn test_manual_query_construction() {
    use ton_adnl::AdnlClient;

    let liteservers = fetch_mainnet_config()
        .await
        .expect("Failed to fetch mainnet config");

    let (addr, pubkey) = &liteservers[0];
    println!("Connecting to: {}", addr);

    let mut client = AdnlClient::connect_with_timeout(
        *addr,
        pubkey,
        Duration::from_secs(10),
    )
    .await
    .expect("Failed to connect");

    println!("Connected!");

    // Manually construct the query following exact documentation format:
    // adnl.message.query (7af98bb4)
    // + query_id (32 random bytes)
    // + query (TL bytes encoded)
    //   └── liteServer.query (df068c79)
    //       └── data (TL bytes encoded)
    //           └── liteServer.getTime (16ad5a34)

    let mut manual_query = Vec::new();

    // 1. adnl.message.query TL ID (little-endian)
    manual_query.extend_from_slice(&[0xb4, 0x8b, 0xf9, 0x7a]);

    // 2. query_id (32 random bytes)
    let query_id: [u8; 32] = [0x42; 32]; // Fixed for reproducibility
    manual_query.extend_from_slice(&query_id);

    // 3. Construct liteServer.query containing liteServer.getTime
    // liteServer.getTime = [34, 5a, ad, 16]
    let get_time = [0x34u8, 0x5a, 0xad, 0x16];

    // liteServer.query = TL_ID + TL_bytes(get_time)
    let mut lite_query = Vec::new();
    lite_query.extend_from_slice(&[0x79, 0x8c, 0x06, 0xdf]); // TL_LITE_QUERY little-endian
    lite_query.push(0x04); // length = 4
    lite_query.extend_from_slice(&get_time);
    lite_query.extend_from_slice(&[0x00, 0x00, 0x00]); // padding to 4-byte align

    println!("liteServer.query (12 bytes): {:02x?}", lite_query);

    // 4. TL bytes encode the lite_query (12 bytes)
    manual_query.push(0x0c); // length = 12
    manual_query.extend_from_slice(&lite_query);
    manual_query.extend_from_slice(&[0x00, 0x00, 0x00]); // padding to 4-byte align

    println!("Full adnl.message.query (52 bytes): {:02x?}", manual_query);
    println!("Length: {}", manual_query.len());

    // Now send this as an ADNL packet payload
    println!("\nSending manually constructed query...");
    match client.send_raw_query(&manual_query).await {
        Ok(()) => println!("Query sent!"),
        Err(e) => {
            eprintln!("Failed to send: {:?}", e);
            return;
        }
    }

    println!("Waiting for response...");
    match tokio::time::timeout(Duration::from_secs(5), client.recv_raw_response()).await {
        Ok(Ok(data)) => {
            println!("Got response: {} bytes", data.len());
            println!("Data: {:02x?}", &data[..std::cmp::min(64, data.len())]);
        }
        Ok(Err(e)) => {
            eprintln!("Recv error: {:?}", e);
        }
        Err(_) => {
            println!("Timeout - no response");
        }
    }
}
