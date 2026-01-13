//! LiteClient implementation for querying TON liteservers.
//!
//! This module provides a high-level client for interacting with TON liteservers
//! using the liteserver protocol over ADNL TCP.
//!
//! # Example
//!
//! ```rust,no_run
//! use ton_adnl::lite_client::LiteClient;
//!
//! async fn example() -> Result<(), Box<dyn std::error::Error>> {
//!     // Connect to a liteserver
//!     let client = LiteClient::connect("1.2.3.4", 12345, &[0u8; 32]).await?;
//!
//!     // Get masterchain info
//!     let info = client.get_masterchain_info().await?;
//!     println!("Last block: {:?}", info.last);
//!
//!     // Get server time
//!     let time = client.get_time().await?;
//!     println!("Server time: {}", time);
//!
//!     Ok(())
//! }
//! ```

use std::net::{SocketAddr, ToSocketAddrs};
use std::time::Duration;

use tokio::sync::Mutex;
use tracing::{debug, trace};

use ton_tl::{TlReader, TlWriter};

use crate::client::AdnlClient;
use crate::error::{AdnlError, Result};
use crate::lite_tl::*;
use crate::lite_types::*;

/// Default timeout for liteserver queries.
const DEFAULT_QUERY_TIMEOUT: Duration = Duration::from_secs(30);

/// LiteClient for querying TON liteservers.
///
/// Provides high-level methods for interacting with the TON blockchain
/// through a liteserver connection.
pub struct LiteClient {
    /// Underlying ADNL client.
    adnl: Mutex<AdnlClient>,
    /// Query timeout.
    timeout: Duration,
}

impl LiteClient {
    /// Connects to a liteserver.
    ///
    /// # Arguments
    ///
    /// * `host` - Hostname or IP address of the liteserver.
    /// * `port` - Port number.
    /// * `server_pubkey` - The server's Ed25519 public key (32 bytes).
    ///
    /// # Returns
    ///
    /// A connected LiteClient ready for queries.
    pub async fn connect(host: &str, port: u16, server_pubkey: &[u8; 32]) -> Result<Self> {
        let addr_str = format!("{}:{}", host, port);
        let addr: SocketAddr = addr_str
            .to_socket_addrs()
            .map_err(|e| AdnlError::HandshakeFailed(format!("DNS resolution failed: {}", e)))?
            .next()
            .ok_or_else(|| AdnlError::HandshakeFailed("No addresses resolved".into()))?;

        Self::connect_addr(addr, server_pubkey).await
    }

    /// Connects to a liteserver using a socket address.
    pub async fn connect_addr(addr: SocketAddr, server_pubkey: &[u8; 32]) -> Result<Self> {
        debug!("Connecting to liteserver at {}", addr);
        let adnl = AdnlClient::connect(addr, server_pubkey).await?;
        debug!("Connected to liteserver");

        Ok(Self {
            adnl: Mutex::new(adnl),
            timeout: DEFAULT_QUERY_TIMEOUT,
        })
    }

    /// Connects to a liteserver with a custom timeout.
    pub async fn connect_with_timeout(
        host: &str,
        port: u16,
        server_pubkey: &[u8; 32],
        timeout: Duration,
    ) -> Result<Self> {
        let addr_str = format!("{}:{}", host, port);
        let addr: SocketAddr = addr_str
            .to_socket_addrs()
            .map_err(|e| AdnlError::HandshakeFailed(format!("DNS resolution failed: {}", e)))?
            .next()
            .ok_or_else(|| AdnlError::HandshakeFailed("No addresses resolved".into()))?;

        let adnl = AdnlClient::connect_with_timeout(addr, server_pubkey, timeout).await?;

        Ok(Self {
            adnl: Mutex::new(adnl),
            timeout,
        })
    }

    /// Sets the query timeout.
    pub fn set_timeout(&mut self, timeout: Duration) {
        self.timeout = timeout;
    }

    /// Returns the current query timeout.
    pub fn timeout(&self) -> Duration {
        self.timeout
    }

    // ========================================================================
    // Basic Queries
    // ========================================================================

    /// Gets information about the current masterchain state.
    ///
    /// Returns the last known masterchain block and zero state.
    pub async fn get_masterchain_info(&self) -> Result<MasterchainInfo> {
        let mut writer = TlWriter::new();
        writer.write_id(TL_LITE_GET_MASTERCHAIN_INFO);

        let response = self.query(writer.as_bytes()).await?;
        let mut reader = TlReader::new(&response);

        let id = reader.read_id().map_err(|e| AdnlError::TlError(e.to_string()))?;
        if id == TL_LITE_ERROR {
            let error = LiteServerError::deserialize(&mut reader)
                .map_err(|e| AdnlError::TlError(e.to_string()))?;
            return Err(AdnlError::TlError(error.to_string()));
        }
        if id != TL_LITE_MASTERCHAIN_INFO {
            return Err(AdnlError::UnexpectedMessageType(id));
        }

        MasterchainInfo::deserialize(&mut reader)
            .map_err(|e| AdnlError::TlError(e.to_string()))
    }

    /// Gets extended information about the masterchain.
    pub async fn get_masterchain_info_ext(&self, mode: u32) -> Result<MasterchainInfoExt> {
        let mut writer = TlWriter::new();
        writer.write_id(TL_LITE_GET_MASTERCHAIN_INFO_EXT);
        writer.write_u32(mode);

        let response = self.query(writer.as_bytes()).await?;
        let mut reader = TlReader::new(&response);

        let id = reader.read_id().map_err(|e| AdnlError::TlError(e.to_string()))?;
        if id == TL_LITE_ERROR {
            let error = LiteServerError::deserialize(&mut reader)
                .map_err(|e| AdnlError::TlError(e.to_string()))?;
            return Err(AdnlError::TlError(error.to_string()));
        }
        if id != TL_LITE_MASTERCHAIN_INFO_EXT {
            return Err(AdnlError::UnexpectedMessageType(id));
        }

        MasterchainInfoExt::deserialize(&mut reader)
            .map_err(|e| AdnlError::TlError(e.to_string()))
    }

    /// Gets the current server time.
    ///
    /// Returns the Unix timestamp from the liteserver.
    pub async fn get_time(&self) -> Result<u32> {
        let mut writer = TlWriter::new();
        writer.write_id(TL_LITE_GET_TIME);

        let response = self.query(writer.as_bytes()).await?;
        let mut reader = TlReader::new(&response);

        let id = reader.read_id().map_err(|e| AdnlError::TlError(e.to_string()))?;
        if id == TL_LITE_ERROR {
            let error = LiteServerError::deserialize(&mut reader)
                .map_err(|e| AdnlError::TlError(e.to_string()))?;
            return Err(AdnlError::TlError(error.to_string()));
        }
        if id != TL_LITE_CURRENT_TIME {
            return Err(AdnlError::UnexpectedMessageType(id));
        }

        reader.read_u32().map_err(|e| AdnlError::TlError(e.to_string()))
    }

    /// Gets the liteserver version information.
    pub async fn get_version(&self) -> Result<LiteServerVersion> {
        let mut writer = TlWriter::new();
        writer.write_id(TL_LITE_GET_VERSION);

        let response = self.query(writer.as_bytes()).await?;
        let mut reader = TlReader::new(&response);

        let id = reader.read_id().map_err(|e| AdnlError::TlError(e.to_string()))?;
        if id == TL_LITE_ERROR {
            let error = LiteServerError::deserialize(&mut reader)
                .map_err(|e| AdnlError::TlError(e.to_string()))?;
            return Err(AdnlError::TlError(error.to_string()));
        }
        if id != TL_LITE_VERSION {
            return Err(AdnlError::UnexpectedMessageType(id));
        }

        LiteServerVersion::deserialize(&mut reader)
            .map_err(|e| AdnlError::TlError(e.to_string()))
    }

    // ========================================================================
    // Block Queries
    // ========================================================================

    /// Gets a block by its extended ID.
    pub async fn get_block(&self, block_id: &BlockIdExt) -> Result<BlockData> {
        let mut writer = TlWriter::new();
        writer.write_id(TL_LITE_GET_BLOCK);
        block_id.serialize(&mut writer);

        let response = self.query(writer.as_bytes()).await?;
        let mut reader = TlReader::new(&response);

        let id = reader.read_id().map_err(|e| AdnlError::TlError(e.to_string()))?;
        if id == TL_LITE_ERROR {
            let error = LiteServerError::deserialize(&mut reader)
                .map_err(|e| AdnlError::TlError(e.to_string()))?;
            return Err(AdnlError::TlError(error.to_string()));
        }
        if id != TL_LITE_BLOCK_DATA {
            return Err(AdnlError::UnexpectedMessageType(id));
        }

        BlockData::deserialize(&mut reader)
            .map_err(|e| AdnlError::TlError(e.to_string()))
    }

    /// Gets a block header.
    pub async fn get_block_header(&self, block_id: &BlockIdExt, mode: u32) -> Result<BlockHeader> {
        let mut writer = TlWriter::new();
        writer.write_id(TL_LITE_GET_BLOCK_HEADER);
        block_id.serialize(&mut writer);
        writer.write_u32(mode);

        let response = self.query(writer.as_bytes()).await?;
        let mut reader = TlReader::new(&response);

        let id = reader.read_id().map_err(|e| AdnlError::TlError(e.to_string()))?;
        if id == TL_LITE_ERROR {
            let error = LiteServerError::deserialize(&mut reader)
                .map_err(|e| AdnlError::TlError(e.to_string()))?;
            return Err(AdnlError::TlError(error.to_string()));
        }
        if id != TL_LITE_BLOCK_HEADER {
            return Err(AdnlError::UnexpectedMessageType(id));
        }

        BlockHeader::deserialize(&mut reader)
            .map_err(|e| AdnlError::TlError(e.to_string()))
    }

    /// Looks up a block by workchain, shard, and either seqno, lt, or utime.
    ///
    /// # Arguments
    ///
    /// * `block_id` - Block ID with workchain, shard, and seqno.
    /// * `mode` - Mode flags:
    ///   - bit 0: Use seqno from block_id
    ///   - bit 1: Use lt parameter
    ///   - bit 2: Use utime parameter
    /// * `lt` - Logical time (if mode & 2).
    /// * `utime` - Unix time (if mode & 4).
    pub async fn lookup_block(
        &self,
        block_id: &BlockId,
        mode: u32,
        lt: u64,
        utime: u32,
    ) -> Result<BlockHeader> {
        let mut writer = TlWriter::new();
        writer.write_id(TL_LITE_LOOKUP_BLOCK);
        writer.write_u32(mode);
        block_id.serialize(&mut writer);
        writer.write_u64(lt);
        writer.write_u32(utime);

        let response = self.query(writer.as_bytes()).await?;
        let mut reader = TlReader::new(&response);

        let id = reader.read_id().map_err(|e| AdnlError::TlError(e.to_string()))?;
        if id == TL_LITE_ERROR {
            let error = LiteServerError::deserialize(&mut reader)
                .map_err(|e| AdnlError::TlError(e.to_string()))?;
            return Err(AdnlError::TlError(error.to_string()));
        }
        if id != TL_LITE_BLOCK_HEADER {
            return Err(AdnlError::UnexpectedMessageType(id));
        }

        BlockHeader::deserialize(&mut reader)
            .map_err(|e| AdnlError::TlError(e.to_string()))
    }

    /// Gets information about all shards at a given masterchain block.
    pub async fn get_all_shards_info(&self, block_id: &BlockIdExt) -> Result<AllShardsInfo> {
        let mut writer = TlWriter::new();
        writer.write_id(TL_LITE_GET_ALL_SHARDS_INFO);
        block_id.serialize(&mut writer);

        let response = self.query(writer.as_bytes()).await?;
        let mut reader = TlReader::new(&response);

        let id = reader.read_id().map_err(|e| AdnlError::TlError(e.to_string()))?;
        if id == TL_LITE_ERROR {
            let error = LiteServerError::deserialize(&mut reader)
                .map_err(|e| AdnlError::TlError(e.to_string()))?;
            return Err(AdnlError::TlError(error.to_string()));
        }
        if id != TL_LITE_ALL_SHARDS_INFO {
            return Err(AdnlError::UnexpectedMessageType(id));
        }

        AllShardsInfo::deserialize(&mut reader)
            .map_err(|e| AdnlError::TlError(e.to_string()))
    }

    /// Gets information about a specific shard.
    pub async fn get_shard_info(
        &self,
        block_id: &BlockIdExt,
        workchain: i32,
        shard: i64,
        exact: bool,
    ) -> Result<ShardInfo> {
        let mut writer = TlWriter::new();
        writer.write_id(TL_LITE_GET_SHARD_INFO);
        block_id.serialize(&mut writer);
        writer.write_i32(workchain);
        writer.write_i64(shard);
        writer.write_bool(exact);

        let response = self.query(writer.as_bytes()).await?;
        let mut reader = TlReader::new(&response);

        let id = reader.read_id().map_err(|e| AdnlError::TlError(e.to_string()))?;
        if id == TL_LITE_ERROR {
            let error = LiteServerError::deserialize(&mut reader)
                .map_err(|e| AdnlError::TlError(e.to_string()))?;
            return Err(AdnlError::TlError(error.to_string()));
        }
        if id != TL_LITE_SHARD_INFO {
            return Err(AdnlError::UnexpectedMessageType(id));
        }

        ShardInfo::deserialize(&mut reader)
            .map_err(|e| AdnlError::TlError(e.to_string()))
    }

    // ========================================================================
    // Account Queries
    // ========================================================================

    /// Gets the state of an account at a specific block.
    pub async fn get_account_state(
        &self,
        block_id: &BlockIdExt,
        address: &AccountAddress,
    ) -> Result<AccountState> {
        let mut writer = TlWriter::new();
        writer.write_id(TL_LITE_GET_ACCOUNT_STATE);
        block_id.serialize(&mut writer);
        address.serialize(&mut writer);

        let response = self.query(writer.as_bytes()).await?;
        let mut reader = TlReader::new(&response);

        let id = reader.read_id().map_err(|e| AdnlError::TlError(e.to_string()))?;
        if id == TL_LITE_ERROR {
            let error = LiteServerError::deserialize(&mut reader)
                .map_err(|e| AdnlError::TlError(e.to_string()))?;
            return Err(AdnlError::TlError(error.to_string()));
        }
        if id != TL_LITE_ACCOUNT_STATE {
            return Err(AdnlError::UnexpectedMessageType(id));
        }

        AccountState::deserialize(&mut reader)
            .map_err(|e| AdnlError::TlError(e.to_string()))
    }

    /// Gets the state of an account at the latest masterchain block.
    pub async fn get_account_state_latest(
        &self,
        address: &AccountAddress,
    ) -> Result<AccountState> {
        let mc_info = self.get_masterchain_info().await?;
        self.get_account_state(&mc_info.last, address).await
    }

    /// Runs a get method on a smart contract.
    ///
    /// # Arguments
    ///
    /// * `block_id` - Block at which to execute the method.
    /// * `address` - Account address.
    /// * `method_id` - Method ID (computed from method name).
    /// * `params` - Serialized stack parameters (BoC).
    /// * `mode` - Mode flags for result fields.
    pub async fn run_get_method(
        &self,
        block_id: &BlockIdExt,
        address: &AccountAddress,
        method_id: u64,
        params: &[u8],
        mode: u32,
    ) -> Result<RunMethodResult> {
        let mut writer = TlWriter::new();
        writer.write_id(TL_LITE_RUN_SMC_METHOD);
        writer.write_u32(mode);
        block_id.serialize(&mut writer);
        address.serialize(&mut writer);
        writer.write_i64(method_id as i64);
        writer.write_bytes(params);

        let response = self.query(writer.as_bytes()).await?;
        let mut reader = TlReader::new(&response);

        let id = reader.read_id().map_err(|e| AdnlError::TlError(e.to_string()))?;
        if id == TL_LITE_ERROR {
            let error = LiteServerError::deserialize(&mut reader)
                .map_err(|e| AdnlError::TlError(e.to_string()))?;
            return Err(AdnlError::TlError(error.to_string()));
        }
        if id != TL_LITE_RUN_RESULT {
            return Err(AdnlError::UnexpectedMessageType(id));
        }

        RunMethodResult::deserialize(&mut reader)
            .map_err(|e| AdnlError::TlError(e.to_string()))
    }

    /// Runs a get method by name on a smart contract at the latest block.
    ///
    /// This is a convenience method that computes the method ID and uses the latest block.
    pub async fn run_get_method_by_name(
        &self,
        address: &AccountAddress,
        method_name: &str,
        params: &[u8],
    ) -> Result<RunMethodResult> {
        let mc_info = self.get_masterchain_info().await?;
        let method_id = compute_method_id(method_name);
        self.run_get_method(&mc_info.last, address, method_id, params, 4).await
    }

    // ========================================================================
    // Transaction Queries
    // ========================================================================

    /// Gets a single transaction by its logical time and block.
    pub async fn get_one_transaction(
        &self,
        block_id: &BlockIdExt,
        address: &AccountAddress,
        lt: u64,
    ) -> Result<TransactionInfo> {
        let mut writer = TlWriter::new();
        writer.write_id(TL_LITE_GET_ONE_TRANSACTION);
        block_id.serialize(&mut writer);
        address.serialize(&mut writer);
        writer.write_u64(lt);

        let response = self.query(writer.as_bytes()).await?;
        let mut reader = TlReader::new(&response);

        let id = reader.read_id().map_err(|e| AdnlError::TlError(e.to_string()))?;
        if id == TL_LITE_ERROR {
            let error = LiteServerError::deserialize(&mut reader)
                .map_err(|e| AdnlError::TlError(e.to_string()))?;
            return Err(AdnlError::TlError(error.to_string()));
        }
        if id != TL_LITE_TRANSACTION_INFO {
            return Err(AdnlError::UnexpectedMessageType(id));
        }

        TransactionInfo::deserialize(&mut reader)
            .map_err(|e| AdnlError::TlError(e.to_string()))
    }

    /// Gets a list of transactions for an account.
    ///
    /// # Arguments
    ///
    /// * `address` - Account address.
    /// * `count` - Maximum number of transactions to return.
    /// * `lt` - Starting logical time (exclusive).
    /// * `hash` - Hash of the transaction at lt.
    pub async fn get_transactions(
        &self,
        address: &AccountAddress,
        count: u32,
        lt: u64,
        hash: &[u8; 32],
    ) -> Result<TransactionList> {
        let mut writer = TlWriter::new();
        writer.write_id(TL_LITE_GET_TRANSACTIONS);
        writer.write_u32(count);
        address.serialize(&mut writer);
        writer.write_u64(lt);
        writer.write_u256(hash);

        let response = self.query(writer.as_bytes()).await?;
        let mut reader = TlReader::new(&response);

        let id = reader.read_id().map_err(|e| AdnlError::TlError(e.to_string()))?;
        if id == TL_LITE_ERROR {
            let error = LiteServerError::deserialize(&mut reader)
                .map_err(|e| AdnlError::TlError(e.to_string()))?;
            return Err(AdnlError::TlError(error.to_string()));
        }
        if id != TL_LITE_TRANSACTION_LIST {
            return Err(AdnlError::UnexpectedMessageType(id));
        }

        TransactionList::deserialize(&mut reader)
            .map_err(|e| AdnlError::TlError(e.to_string()))
    }

    /// Lists transactions in a block.
    ///
    /// # Arguments
    ///
    /// * `block_id` - Block to list transactions from.
    /// * `mode` - Mode flags:
    ///   - bit 5: Include proof
    ///   - bit 6: Reverse order
    ///   - bit 7: After specific transaction
    /// * `count` - Maximum number of transactions.
    /// * `after` - Transaction to start after (if mode & 128).
    pub async fn list_block_transactions(
        &self,
        block_id: &BlockIdExt,
        mode: u32,
        count: u32,
        after: Option<&TransactionId3>,
    ) -> Result<BlockTransactions> {
        let mut writer = TlWriter::new();
        writer.write_id(TL_LITE_LIST_BLOCK_TRANSACTIONS);
        block_id.serialize(&mut writer);
        writer.write_u32(mode);
        writer.write_u32(count);

        if let Some(tx_id) = after && mode & 128 != 0 {
            tx_id.serialize(&mut writer);
        }

        let response = self.query(writer.as_bytes()).await?;
        let mut reader = TlReader::new(&response);

        let id = reader.read_id().map_err(|e| AdnlError::TlError(e.to_string()))?;
        if id == TL_LITE_ERROR {
            let error = LiteServerError::deserialize(&mut reader)
                .map_err(|e| AdnlError::TlError(e.to_string()))?;
            return Err(AdnlError::TlError(error.to_string()));
        }
        if id != TL_LITE_BLOCK_TRANSACTIONS {
            return Err(AdnlError::UnexpectedMessageType(id));
        }

        BlockTransactions::deserialize(&mut reader)
            .map_err(|e| AdnlError::TlError(e.to_string()))
    }

    // ========================================================================
    // Config Queries
    // ========================================================================

    /// Gets the full blockchain configuration.
    pub async fn get_config_all(&self, block_id: &BlockIdExt, mode: u32) -> Result<ConfigInfo> {
        let mut writer = TlWriter::new();
        writer.write_id(TL_LITE_GET_CONFIG_ALL);
        writer.write_u32(mode);
        block_id.serialize(&mut writer);

        let response = self.query(writer.as_bytes()).await?;
        let mut reader = TlReader::new(&response);

        let id = reader.read_id().map_err(|e| AdnlError::TlError(e.to_string()))?;
        if id == TL_LITE_ERROR {
            let error = LiteServerError::deserialize(&mut reader)
                .map_err(|e| AdnlError::TlError(e.to_string()))?;
            return Err(AdnlError::TlError(error.to_string()));
        }
        if id != TL_LITE_CONFIG_INFO {
            return Err(AdnlError::UnexpectedMessageType(id));
        }

        ConfigInfo::deserialize(&mut reader)
            .map_err(|e| AdnlError::TlError(e.to_string()))
    }

    /// Gets specific configuration parameters.
    pub async fn get_config_params(
        &self,
        block_id: &BlockIdExt,
        mode: u32,
        params: &[i32],
    ) -> Result<ConfigInfo> {
        let mut writer = TlWriter::new();
        writer.write_id(TL_LITE_GET_CONFIG_PARAMS);
        writer.write_u32(mode);
        block_id.serialize(&mut writer);
        writer.write_vector_bare(params, |w, &p| w.write_i32(p));

        let response = self.query(writer.as_bytes()).await?;
        let mut reader = TlReader::new(&response);

        let id = reader.read_id().map_err(|e| AdnlError::TlError(e.to_string()))?;
        if id == TL_LITE_ERROR {
            let error = LiteServerError::deserialize(&mut reader)
                .map_err(|e| AdnlError::TlError(e.to_string()))?;
            return Err(AdnlError::TlError(error.to_string()));
        }
        if id != TL_LITE_CONFIG_INFO {
            return Err(AdnlError::UnexpectedMessageType(id));
        }

        ConfigInfo::deserialize(&mut reader)
            .map_err(|e| AdnlError::TlError(e.to_string()))
    }

    // ========================================================================
    // Send Message
    // ========================================================================

    /// Sends an external message to the blockchain.
    ///
    /// # Arguments
    ///
    /// * `body` - The message body as BoC (Bag of Cells).
    pub async fn send_message(&self, body: &[u8]) -> Result<SendMsgStatus> {
        let mut writer = TlWriter::new();
        writer.write_id(TL_LITE_SEND_MESSAGE);
        writer.write_bytes(body);

        let response = self.query(writer.as_bytes()).await?;
        let mut reader = TlReader::new(&response);

        let id = reader.read_id().map_err(|e| AdnlError::TlError(e.to_string()))?;
        if id == TL_LITE_ERROR {
            let error = LiteServerError::deserialize(&mut reader)
                .map_err(|e| AdnlError::TlError(e.to_string()))?;
            return Err(AdnlError::TlError(error.to_string()));
        }
        if id != TL_LITE_SEND_MSG_STATUS {
            return Err(AdnlError::UnexpectedMessageType(id));
        }

        SendMsgStatus::deserialize(&mut reader)
            .map_err(|e| AdnlError::TlError(e.to_string()))
    }

    // ========================================================================
    // Wait for Block
    // ========================================================================

    /// Waits for a specific masterchain seqno to be available.
    ///
    /// # Arguments
    ///
    /// * `seqno` - The sequence number to wait for.
    /// * `timeout_ms` - Timeout in milliseconds.
    pub async fn wait_masterchain_seqno(&self, seqno: u32, timeout_ms: u32) -> Result<()> {
        let mut writer = TlWriter::new();
        writer.write_id(TL_LITE_WAIT_MASTERCHAIN_SEQNO);
        writer.write_u32(seqno);
        writer.write_u32(timeout_ms);

        // This query will block until the seqno is available or timeout
        let _response = self.query(writer.as_bytes()).await?;
        Ok(())
    }

    // ========================================================================
    // Low-level Query
    // ========================================================================

    /// Sends a raw query to the liteserver.
    ///
    /// The query data should NOT include the liteServer.query wrapper - this
    /// method wraps the query automatically.
    async fn query(&self, data: &[u8]) -> Result<Vec<u8>> {
        // Wrap the query with liteServer.query
        let wrapped = wrap_lite_query(data);

        trace!("Sending liteserver query: {} bytes", wrapped.len());

        let mut adnl = self.adnl.lock().await;
        adnl.query(&wrapped).await
    }

    /// Sends a raw query without wrapping.
    ///
    /// Use this if you need to send a pre-wrapped query.
    pub async fn query_raw(&self, data: &[u8]) -> Result<Vec<u8>> {
        let mut adnl = self.adnl.lock().await;
        adnl.query(data).await
    }

    /// Sends a ping to keep the connection alive.
    pub async fn ping(&self) -> Result<()> {
        let mut adnl = self.adnl.lock().await;
        adnl.ping().await
    }

    /// Gracefully shuts down the connection.
    pub async fn shutdown(&self) -> Result<()> {
        let mut adnl = self.adnl.lock().await;
        adnl.shutdown().await
    }
}

impl std::fmt::Debug for LiteClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LiteClient")
            .field("timeout", &self.timeout)
            .finish()
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Wraps a query with the liteServer.query TL constructor.
fn wrap_lite_query(data: &[u8]) -> Vec<u8> {
    let mut writer = TlWriter::new();
    writer.write_id(TL_LITE_QUERY);
    writer.write_bytes(data);
    writer.into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wrap_lite_query() {
        let data = [0x01, 0x02, 0x03, 0x04];
        let wrapped = wrap_lite_query(&data);

        let mut reader = TlReader::new(&wrapped);
        let id = reader.read_id().unwrap();
        assert_eq!(id, TL_LITE_QUERY);

        let inner = reader.read_bytes().unwrap();
        assert_eq!(inner, data);
    }

    #[test]
    fn test_default_timeout() {
        assert_eq!(DEFAULT_QUERY_TIMEOUT, Duration::from_secs(30));
    }
}
