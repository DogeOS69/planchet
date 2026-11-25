use crate::{
    BlockCheck, Client, Error, check_raw_block,
    types::{self, BlockVerbosity, RpcBlockHash, RpcTxid},
};
use planchet_consensus::{BaseHeader, DecodeLimits, WireHeader};
use planchet_primitives::{BlockHash, Network, OutPoint, Txid, sha256d};
use planchet_transport::Transport;

#[derive(Clone, Debug)]
pub struct Provider<T> {
    client: Client<T>,
    verbosity: BlockVerbosity,
}
impl<T: Transport> Provider<T> {
    pub fn new(transport: T) -> Self {
        Self::from_client(Client::new(transport))
    }
    pub fn from_client(client: Client<T>) -> Self {
        Self {
            client,
            verbosity: BlockVerbosity::Numeric,
        }
    }
    pub fn with_block_verbosity(mut self, verbosity: BlockVerbosity) -> Self {
        self.verbosity = verbosity;
        self
    }
    pub fn client(&self) -> &Client<T> {
        &self.client
    }
    pub async fn blockchain_info(&self) -> Result<types::BlockchainInfo, Error> {
        self.client.call("getblockchaininfo", [] as [u8; 0]).await
    }
    pub async fn block_count(&self) -> Result<u64, Error> {
        self.client.call("getblockcount", [] as [u8; 0]).await
    }
    pub async fn best_block_hash(&self) -> Result<BlockHash, Error> {
        self.client
            .call::<_, RpcBlockHash>("getbestblockhash", [] as [u8; 0])
            .await
            .map(|v| v.0)
    }
    pub async fn block_hash(&self, height: u64) -> Result<BlockHash, Error> {
        self.client
            .call::<_, RpcBlockHash>("getblockhash", [height])
            .await
            .map(|v| v.0)
    }
    pub async fn network_info(&self) -> Result<types::NetworkInfo, Error> {
        self.client.call("getnetworkinfo", [] as [u8; 0]).await
    }
    pub async fn chain_tips(&self) -> Result<Vec<types::ChainTip>, Error> {
        self.client.call("getchaintips", [] as [u8; 0]).await
    }
    /// Checks both independent node identity observations. Does not infer identity from prefixes.
    pub async fn validate_network(
        &self,
        expected: Network,
    ) -> Result<types::BlockchainInfo, Error> {
        let info = self.blockchain_info().await?;
        let genesis = self.block_hash(0).await?;
        if info.chain != expected.core_name() || genesis != expected.genesis_hash() {
            return Err(Error::NetworkMismatch {
                expected,
                chain: info.chain,
                genesis,
            });
        }
        Ok(info)
    }
    pub async fn raw_block(&self, hash: BlockHash) -> Result<Vec<u8>, Error> {
        let text: String = match self.verbosity {
            BlockVerbosity::Numeric => self.client.call("getblock", (hash.to_string(), 0)).await?,
            BlockVerbosity::LegacyBoolean => {
                self.client
                    .call("getblock", (hash.to_string(), false))
                    .await?
            }
        };
        let bytes = decode_hex(&text, "getblock")?;
        check_header_id(&bytes, hash, "getblock")?;
        Ok(bytes)
    }
    pub async fn block_info(&self, hash: BlockHash) -> Result<types::BlockInfo, Error> {
        let info: types::BlockInfo = match self.verbosity {
            BlockVerbosity::Numeric => self.client.call("getblock", (hash.to_string(), 1)).await?,
            BlockVerbosity::LegacyBoolean => {
                self.client
                    .call("getblock", (hash.to_string(), true))
                    .await?
            }
        };
        ensure_hash(hash, info.header.hash)?;
        Ok(info)
    }
    /// Complete serialized native/AuxPoW wire header, with exact decoding and ID checking.
    /// Some Core builds return only the 80-byte base for AuxPoW. That incomplete response
    /// is rejected here; use `base_block_header` for just the base, or `raw_block` to
    /// obtain the full AuxPoW payload. No second request is sent automatically.
    pub async fn raw_block_header(&self, hash: BlockHash) -> Result<Vec<u8>, Error> {
        let text: String = self
            .client
            .call("getblockheader", (hash.to_string(), false))
            .await?;
        let bytes = decode_hex(&text, "getblockheader")?;
        let header = WireHeader::decode_exact(&bytes, DecodeLimits::default()).map_err(|_| {
            Error::InvalidResponse {
                method: "getblockheader".into(),
                reason: "invalid or incomplete wire header; an AuxPoW base alone is not complete",
            }
        })?;
        ensure_hash(hash, header.block_id())?;
        Ok(bytes)
    }
    /// The 80-byte child/native header only; makes no claim about an AuxPoW payload.
    pub async fn base_block_header(&self, hash: BlockHash) -> Result<BaseHeader, Error> {
        let text: String = self
            .client
            .call("getblockheader", (hash.to_string(), false))
            .await?;
        let bytes = decode_hex(&text, "getblockheader")?;
        let (header, _) =
            BaseHeader::decode_prefix(&bytes).map_err(|_| Error::InvalidResponse {
                method: "getblockheader".into(),
                reason: "invalid base header",
            })?;
        ensure_hash(hash, header.block_id())?;
        Ok(header)
    }
    pub async fn block_header(&self, hash: BlockHash) -> Result<types::BlockHeader, Error> {
        let header: types::BlockHeader = self
            .client
            .call("getblockheader", (hash.to_string(), true))
            .await?;
        ensure_hash(hash, header.hash)?;
        Ok(header)
    }
    /// Returns a checked block observation bracketed by reads of the same height.
    /// This is ID/Merkle checking, not PoW, script, or full-chain consensus validation.
    pub async fn check_block_at_height(&self, height: u64) -> Result<BlockCheck, Error> {
        let anchor = self.block_hash(height).await?;
        let bytes = self.raw_block(anchor).await?;
        let check = check_raw_block(&bytes, Some(anchor))?;
        let after = self.block_hash(height).await?;
        if anchor != after {
            return Err(Error::AnchorChanged {
                height,
                before: anchor,
                after,
            });
        }
        Ok(check)
    }
    pub async fn raw_mempool(&self) -> Result<Vec<Txid>, Error> {
        let ids: Vec<RpcTxid> = self.client.call("getrawmempool", [false]).await?;
        Ok(ids.into_iter().map(|v| v.0).collect())
    }
    pub async fn mempool_info(&self) -> Result<types::MempoolInfo, Error> {
        self.client.call("getmempoolinfo", [] as [u8; 0]).await
    }
    /// Null means this output was not observed in the selected view. It is not classified as spent.
    pub async fn tx_out(
        &self,
        outpoint: OutPoint,
        view: types::SpendView,
    ) -> Result<Option<types::TxOut>, Error> {
        self.client
            .call(
                "gettxout",
                (
                    outpoint.txid.to_string(),
                    outpoint.vout,
                    view.include_mempool(),
                ),
            )
            .await
    }
    pub async fn raw_transaction(&self, txid: Txid) -> Result<Vec<u8>, Error> {
        let text: String = self
            .client
            .call("getrawtransaction", (txid.to_string(), false))
            .await?;
        let bytes = decode_hex(&text, "getrawtransaction")?;
        if Txid::from_wire_bytes(sha256d(&bytes)) != txid {
            return Err(Error::InvalidResponse {
                method: "getrawtransaction".into(),
                reason: "returned transaction has a different txid",
            });
        }
        Ok(bytes)
    }
    pub async fn transaction_info(&self, txid: Txid) -> Result<types::TransactionInfo, Error> {
        let info: types::TransactionInfo = self
            .client
            .call("getrawtransaction", (txid.to_string(), true))
            .await?;
        if info.txid != txid {
            return Err(Error::InvalidResponse {
                method: "getrawtransaction".into(),
                reason: "returned DTO has a different txid",
            });
        }
        Ok(info)
    }
    pub async fn decode_transaction(&self, bytes: &[u8]) -> Result<types::TransactionInfo, Error> {
        let info: types::TransactionInfo = self
            .client
            .call("decoderawtransaction", [encode_hex(bytes)])
            .await?;
        if info.txid != Txid::from_wire_bytes(sha256d(bytes)) {
            return Err(Error::InvalidResponse {
                method: "decoderawtransaction".into(),
                reason: "returned DTO has a different txid",
            });
        }
        Ok(info)
    }
    pub async fn mempool_entry(&self, txid: Txid) -> Result<types::MempoolEntry, Error> {
        self.client
            .call("getmempoolentry", [txid.to_string()])
            .await
    }
    /// Brackets chain observations with the best tip. Mempool observations remain ephemeral:
    /// a stable chain tip cannot prove that the mempool remained unchanged.
    pub async fn utxo_status(
        &self,
        outpoint: OutPoint,
        view: types::SpendView,
    ) -> Result<UtxoObservation, Error> {
        let before = self.best_block_hash().await?;
        let status = self.observe_utxo(outpoint, view, before).await?;
        let after = self.best_block_hash().await?;
        if before != after {
            return Err(Error::TipChanged { before, after });
        }
        Ok(UtxoObservation {
            view,
            tip: after,
            status,
        })
    }
    async fn observe_utxo(
        &self,
        outpoint: OutPoint,
        view: types::SpendView,
        tip: BlockHash,
    ) -> Result<UtxoStatus, Error> {
        if let Some(output) = self.tx_out(outpoint, view).await? {
            if output.bestblock != tip {
                return Err(Error::TipChanged {
                    before: tip,
                    after: output.bestblock,
                });
            }
            if view == types::SpendView::ConfirmedOnly && output.confirmations == 0 {
                return Ok(UtxoStatus::Unknown(UtxoUnknown::ParentNotActive));
            }
            return Ok(UtxoStatus::Unspent(Box::new(output)));
        }
        let parent = match self.transaction_info(outpoint.txid).await {
            Ok(parent) => parent,
            Err(Error::Rpc { code: -5, .. }) => {
                return Ok(UtxoStatus::Unknown(UtxoUnknown::ParentUnavailable));
            }
            Err(error) => return Err(error),
        };
        if !parent.vout.iter().any(|o| o.n == outpoint.vout) {
            return Ok(UtxoStatus::Unknown(UtxoUnknown::InvalidOutputIndex));
        }
        if parent.confirmations.is_some_and(|n| n > 0) {
            if let Some(blockhash) = parent.blockhash {
                let header = self.block_header(blockhash).await?;
                if header.confirmations > 0 && self.block_hash(header.height).await? == blockhash {
                    return Ok(UtxoStatus::Spent {
                        parent_block: Some(blockhash),
                    });
                }
            }
            return Ok(UtxoStatus::Unknown(UtxoUnknown::ParentNotActive));
        }
        if view == types::SpendView::ConfirmedOnly || parent.blockhash.is_some() {
            return Ok(UtxoStatus::Unknown(UtxoUnknown::ParentNotActive));
        }
        match self.mempool_entry(outpoint.txid).await {
            Ok(_) => Ok(UtxoStatus::Spent { parent_block: None }),
            Err(Error::Rpc { code: -5, .. }) => {
                Ok(UtxoStatus::Unknown(UtxoUnknown::ParentNotObservedInMempool))
            }
            Err(error) => Err(error),
        }
    }
    /// Submit these exact signed bytes once. Caller owns reconciliation and any later retry.
    pub async fn broadcast(&self, signed_bytes: &[u8]) -> Result<Txid, Error> {
        let txid = Txid::from_wire_bytes(sha256d(signed_bytes));
        match self
            .client
            .call::<_, RpcTxid>("sendrawtransaction", [encode_hex(signed_bytes)])
            .await
        {
            Ok(actual) if actual.0 == txid => Ok(txid),
            Ok(actual) => Err(Error::BroadcastTxidMismatch {
                expected: txid,
                actual: actual.0,
            }),
            Err(error @ Error::Rpc { .. }) => Err(error),
            Err(error) => Err(Error::SubmissionUnknown {
                txid,
                cause: Box::new(error),
            }),
        }
    }
}
fn ensure_hash(expected: BlockHash, actual: BlockHash) -> Result<(), Error> {
    if expected != actual {
        Err(Error::HashMismatch { expected, actual })
    } else {
        Ok(())
    }
}
fn check_header_id(bytes: &[u8], expected: BlockHash, method: &str) -> Result<(), Error> {
    let header = bytes.get(..80).ok_or_else(|| Error::InvalidResponse {
        method: method.into(),
        reason: "raw data is shorter than a base block header",
    })?;
    ensure_hash(expected, BlockHash::from_wire_bytes(sha256d(header)))
}
pub(crate) fn decode_hex(text: &str, method: &str) -> Result<Vec<u8>, Error> {
    let invalid = || Error::InvalidResponse {
        method: method.into(),
        reason: "invalid raw hexadecimal data",
    };
    if !text.len().is_multiple_of(2) {
        return Err(invalid());
    }
    text.as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let nibble = |b: u8| match b {
                b'0'..=b'9' => Some(b - b'0'),
                b'a'..=b'f' => Some(b - b'a' + 10),
                b'A'..=b'F' => Some(b - b'A' + 10),
                _ => None,
            };
            Ok(nibble(pair[0]).ok_or_else(invalid)? * 16 + nibble(pair[1]).ok_or_else(invalid)?)
        })
        .collect()
}
fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut text = String::with_capacity(bytes.len().saturating_mul(2));
    for b in bytes {
        text.push(HEX[(b >> 4) as usize] as char);
        text.push(HEX[(b & 15) as usize] as char);
    }
    text
}

#[derive(Clone, Debug)]
pub struct UtxoObservation {
    pub view: types::SpendView,
    pub tip: BlockHash,
    pub status: UtxoStatus,
}
#[derive(Clone, Debug)]
pub enum UtxoStatus {
    Unspent(Box<types::TxOut>),
    Spent { parent_block: Option<BlockHash> },
    Unknown(UtxoUnknown),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UtxoUnknown {
    ParentUnavailable,
    InvalidOutputIndex,
    ParentNotActive,
    ParentNotObservedInMempool,
}
