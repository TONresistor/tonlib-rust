//! TL schema IDs for LiteServer protocol.
//!
//! These are the constructor IDs (CRC32 of the TL schema) used in the
//! liteserver query/response protocol.
//!
//! IDs sourced from: https://github.com/tonkeeper/tongo/blob/master/liteclient/lite_api.tl

// ============================================================================
// Query Wrappers
// ============================================================================

/// liteServer.query data:bytes = Object
pub const TL_LITE_QUERY: u32 = 0xdf068c79;

/// liteServer.waitMasterchainSeqno seqno:int timeout:int = Object
pub const TL_LITE_WAIT_MASTERCHAIN_SEQNO: u32 = 0xbca8b453;

// ============================================================================
// Query Types (client -> liteserver)
// ============================================================================

/// liteServer.getMasterchainInfo = liteServer.MasterchainInfo
pub const TL_LITE_GET_MASTERCHAIN_INFO: u32 = 0x89b5e62e;

/// liteServer.getMasterchainInfoExt mode:int = liteServer.MasterchainInfoExt
pub const TL_LITE_GET_MASTERCHAIN_INFO_EXT: u32 = 0x70a671df;

/// liteServer.getTime = liteServer.CurrentTime
pub const TL_LITE_GET_TIME: u32 = 0x16ad5a34;

/// liteServer.getVersion = liteServer.Version
pub const TL_LITE_GET_VERSION: u32 = 0x232b940b;

/// liteServer.getBlock id:tonNode.blockIdExt = liteServer.BlockData
pub const TL_LITE_GET_BLOCK: u32 = 0x6377cf0d;

/// liteServer.getState id:tonNode.blockIdExt = liteServer.BlockState
pub const TL_LITE_GET_STATE: u32 = 0xba6e2eb6;

/// liteServer.getBlockHeader id:tonNode.blockIdExt mode:# = liteServer.BlockHeader
pub const TL_LITE_GET_BLOCK_HEADER: u32 = 0x21ec069e;

/// liteServer.sendMessage body:bytes = liteServer.SendMsgStatus
pub const TL_LITE_SEND_MESSAGE: u32 = 0x690ad482;

/// liteServer.getAccountState id:tonNode.blockIdExt account:liteServer.accountId = liteServer.AccountState
pub const TL_LITE_GET_ACCOUNT_STATE: u32 = 0x6b890e25;

/// liteServer.runSmcMethod mode:# id:tonNode.blockIdExt account:liteServer.accountId method_id:long params:bytes = liteServer.RunMethodResult
pub const TL_LITE_RUN_SMC_METHOD: u32 = 0x5cc65dd2;

/// liteServer.getShardInfo id:tonNode.blockIdExt workchain:int shard:long exact:Bool = liteServer.ShardInfo
pub const TL_LITE_GET_SHARD_INFO: u32 = 0x46a2f425;

/// liteServer.getAllShardsInfo id:tonNode.blockIdExt = liteServer.AllShardsInfo
pub const TL_LITE_GET_ALL_SHARDS_INFO: u32 = 0x74d3fd6b;

/// liteServer.getOneTransaction id:tonNode.blockIdExt account:liteServer.accountId lt:long = liteServer.TransactionInfo
pub const TL_LITE_GET_ONE_TRANSACTION: u32 = 0xd40f24ea;

/// liteServer.getTransactions count:# account:liteServer.accountId lt:long hash:int256 = liteServer.TransactionList
pub const TL_LITE_GET_TRANSACTIONS: u32 = 0x1c40e7a1;

/// liteServer.getConfigAll mode:# id:tonNode.blockIdExt = liteServer.ConfigInfo
pub const TL_LITE_GET_CONFIG_ALL: u32 = 0x911b26b7;

/// liteServer.getConfigParams mode:# id:tonNode.blockIdExt param_list:(vector int) = liteServer.ConfigInfo
pub const TL_LITE_GET_CONFIG_PARAMS: u32 = 0x2a111c19;

/// liteServer.lookupBlock mode:# id:tonNode.blockId lt:long utime:int = liteServer.BlockHeader
pub const TL_LITE_LOOKUP_BLOCK: u32 = 0xfac8f71e;

/// liteServer.getBlockProof mode:# known_block:tonNode.blockIdExt target_block:mode.0?tonNode.blockIdExt = liteServer.PartialBlockProof
pub const TL_LITE_GET_BLOCK_PROOF: u32 = 0x8aea9c44;

/// liteServer.listBlockTransactions id:tonNode.blockIdExt mode:# count:# after:mode.7?liteServer.transactionId3 reverse_order:mode.6?true want_proof:mode.5?true = liteServer.BlockTransactions
pub const TL_LITE_LIST_BLOCK_TRANSACTIONS: u32 = 0xadfcc7da;

/// liteServer.getValidatorStats mode:# id:tonNode.blockIdExt limit:int start_after:mode.0?int256 modified_after:mode.2?int = liteServer.ValidatorStats
pub const TL_LITE_GET_VALIDATOR_STATS: u32 = 0x091a58bc;

/// liteServer.getLibraries library_list:(vector int256) = liteServer.LibraryResult
pub const TL_LITE_GET_LIBRARIES: u32 = 0xd122b662;

// ============================================================================
// Response Types (liteserver -> client)
// ============================================================================

/// liteServer.masterchainInfo last:tonNode.blockIdExt state_root_hash:int256 init:tonNode.zeroStateIdExt = liteServer.MasterchainInfo
pub const TL_LITE_MASTERCHAIN_INFO: u32 = 0x85832881;

/// liteServer.masterchainInfoExt mode:# version:int capabilities:long last:tonNode.blockIdExt last_utime:int now:int state_root_hash:int256 init:tonNode.zeroStateIdExt = liteServer.MasterchainInfoExt
pub const TL_LITE_MASTERCHAIN_INFO_EXT: u32 = 0xa8cce0f5;

/// liteServer.currentTime now:int = liteServer.CurrentTime
pub const TL_LITE_CURRENT_TIME: u32 = 0xe953000d;

/// liteServer.version mode:# version:int capabilities:long now:int = liteServer.Version
pub const TL_LITE_VERSION: u32 = 0x5a0491e5;

/// liteServer.blockData id:tonNode.blockIdExt data:bytes = liteServer.BlockData
pub const TL_LITE_BLOCK_DATA: u32 = 0xa574ed6c;

/// liteServer.blockState id:tonNode.blockIdExt root_hash:int256 file_hash:int256 data:bytes = liteServer.BlockState
pub const TL_LITE_BLOCK_STATE: u32 = 0xabaddc0c;

/// liteServer.blockHeader id:tonNode.blockIdExt mode:# header_proof:bytes = liteServer.BlockHeader
pub const TL_LITE_BLOCK_HEADER: u32 = 0x752d8219;

/// liteServer.sendMsgStatus status:int = liteServer.SendMsgStatus
pub const TL_LITE_SEND_MSG_STATUS: u32 = 0x3950e597;

/// liteServer.accountState id:tonNode.blockIdExt shardblk:tonNode.blockIdExt shard_proof:bytes proof:bytes state:bytes = liteServer.AccountState
pub const TL_LITE_ACCOUNT_STATE: u32 = 0x7079c751;

/// liteServer.runMethodResult mode:# id:tonNode.blockIdExt shardblk:tonNode.blockIdExt shard_proof:mode.0?bytes proof:mode.0?bytes state_proof:mode.1?bytes init_c7:mode.3?bytes lib_extras:mode.4?bytes exit_code:int result:mode.2?bytes = liteServer.RunMethodResult
pub const TL_LITE_RUN_RESULT: u32 = 0xa39a616b;

/// liteServer.shardInfo id:tonNode.blockIdExt shardblk:tonNode.blockIdExt shard_proof:bytes shard_descr:bytes = liteServer.ShardInfo
pub const TL_LITE_SHARD_INFO: u32 = 0x9fe6cd84;

/// liteServer.allShardsInfo id:tonNode.blockIdExt proof:bytes data:bytes = liteServer.AllShardsInfo
pub const TL_LITE_ALL_SHARDS_INFO: u32 = 0x098fe72d;

/// liteServer.transactionInfo id:tonNode.blockIdExt proof:bytes transaction:bytes = liteServer.TransactionInfo
pub const TL_LITE_TRANSACTION_INFO: u32 = 0x0edeed47;

/// liteServer.transactionList ids:(vector tonNode.blockIdExt) transactions:bytes = liteServer.TransactionList
pub const TL_LITE_TRANSACTION_LIST: u32 = 0x6f26c60b;

/// liteServer.configInfo mode:# id:tonNode.blockIdExt state_proof:bytes config_proof:bytes = liteServer.ConfigInfo
pub const TL_LITE_CONFIG_INFO: u32 = 0xae7b272f;

/// liteServer.partialBlockProof complete:Bool from:tonNode.blockIdExt to:tonNode.blockIdExt steps:(vector liteServer.BlockLink) = liteServer.PartialBlockProof
pub const TL_LITE_PARTIAL_BLOCK_PROOF: u32 = 0x8ed0d2c1;

/// liteServer.blockTransactions id:tonNode.blockIdExt req_count:# incomplete:Bool ids:(vector liteServer.transactionId) proof:bytes = liteServer.BlockTransactions
pub const TL_LITE_BLOCK_TRANSACTIONS: u32 = 0xbd8cad2b;

/// liteServer.validatorStats mode:# id:tonNode.blockIdExt count:int complete:Bool state_proof:bytes data_proof:bytes = liteServer.ValidatorStats
pub const TL_LITE_VALIDATOR_STATS: u32 = 0xb9f796d8;

/// liteServer.libraryResult result:(vector liteServer.libraryEntry) = liteServer.LibraryResult
pub const TL_LITE_LIBRARY_RESULT: u32 = 0x117ab96b;

// ============================================================================
// Common Types
// ============================================================================

/// tonNode.blockIdExt workchain:int shard:long seqno:int root_hash:int256 file_hash:int256 = tonNode.BlockIdExt
pub const TL_TON_NODE_BLOCK_ID_EXT: u32 = 0x5c008f5a;

/// tonNode.blockId workchain:int shard:long seqno:int = tonNode.BlockId
pub const TL_TON_NODE_BLOCK_ID: u32 = 0x7f8f8c49;

/// tonNode.zeroStateIdExt workchain:int root_hash:int256 file_hash:int256 = tonNode.ZeroStateIdExt
pub const TL_TON_NODE_ZERO_STATE_ID_EXT: u32 = 0xa60fe7be;

/// liteServer.accountId workchain:int id:int256 = liteServer.AccountId
pub const TL_LITE_ACCOUNT_ID: u32 = 0x480eae86;

/// liteServer.transactionId mode:# account:mode.0?int256 lt:mode.1?long hash:mode.2?int256 = liteServer.TransactionId
pub const TL_LITE_TRANSACTION_ID: u32 = 0xb12f65af;

/// liteServer.transactionId3 account:int256 lt:long = liteServer.TransactionId3
pub const TL_LITE_TRANSACTION_ID3: u32 = 0xc7f7b4d3;

/// liteServer.libraryEntry hash:int256 data:bytes = liteServer.LibraryEntry
pub const TL_LITE_LIBRARY_ENTRY: u32 = 0x7f93bbaf;

// ============================================================================
// Error Types
// ============================================================================

/// liteServer.error code:int message:string = liteServer.Error
pub const TL_LITE_ERROR: u32 = 0xbba9e148;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_query_schema_ids() {
        // Verify some key schema IDs (from tongo/liteclient/lite_api.tl)
        assert_eq!(TL_LITE_QUERY, 0xdf068c79);
        assert_eq!(TL_LITE_GET_MASTERCHAIN_INFO, 0x89b5e62e);
        assert_eq!(TL_LITE_GET_TIME, 0x16ad5a34);
        assert_eq!(TL_LITE_GET_VERSION, 0x232b940b);
        assert_eq!(TL_LITE_GET_ACCOUNT_STATE, 0x6b890e25);
        assert_eq!(TL_LITE_RUN_SMC_METHOD, 0x5cc65dd2);
    }

    #[test]
    fn test_response_schema_ids() {
        assert_eq!(TL_LITE_MASTERCHAIN_INFO, 0x85832881);
        assert_eq!(TL_LITE_CURRENT_TIME, 0xe953000d);
        assert_eq!(TL_LITE_VERSION, 0x5a0491e5);
        assert_eq!(TL_LITE_ACCOUNT_STATE, 0x7079c751);
        assert_eq!(TL_LITE_RUN_RESULT, 0xa39a616b);
    }

    #[test]
    fn test_common_type_schema_ids() {
        assert_eq!(TL_TON_NODE_BLOCK_ID_EXT, 0x5c008f5a);
        assert_eq!(TL_TON_NODE_BLOCK_ID, 0x7f8f8c49);
        assert_eq!(TL_LITE_ACCOUNT_ID, 0x480eae86);
        assert_eq!(TL_LITE_ERROR, 0xbba9e148);
    }
}
