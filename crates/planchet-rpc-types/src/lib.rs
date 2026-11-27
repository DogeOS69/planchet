//! Dogecoin Core RPC DTOs. Numeric tokens retain their source text; amounts never use floats.
#![no_std]
#![forbid(unsafe_code)]
extern crate alloc;

mod number;
use alloc::{string::String, vec::Vec};
pub use number::{AmountError, JsonNumber, RpcAmount};
use planchet_primitives::{BlockHash, MerkleRoot, Txid, Wtxid};
use serde::{Deserialize, Serialize};

/// Selects a block by hash, active-chain height, or the latest observed tip.
/// A resolved block can become stale.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlockId {
    /// A fixed block hash.
    Hash(BlockHash),
    /// An active-chain height resolved with `getblockhash` when awaited.
    Height(u64),
    /// The tip resolved with `getbestblockhash` when awaited.
    Latest,
}

/// Serde at the RPC boundary uses the primitives' canonical display/parser contract.
pub mod hash {
    use super::*;
    use core::{fmt::Display, str::FromStr};
    pub fn serialize<S: serde::Serializer, T: Display>(value: &T, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(value)
    }
    pub fn deserialize<'de, D: serde::Deserializer<'de>, T: FromStr>(d: D) -> Result<T, D::Error> {
        String::deserialize(d)?
            .parse()
            .map_err(|_| serde::de::Error::custom("invalid RPC hash"))
    }
}
mod optional_hash {
    use super::*;
    pub fn deserialize<'de, D: serde::Deserializer<'de>>(
        d: D,
    ) -> Result<Option<BlockHash>, D::Error> {
        Option::<String>::deserialize(d)?
            .map(|v| {
                v.parse()
                    .map_err(|_| serde::de::Error::custom("invalid RPC hash"))
            })
            .transpose()
    }
}
mod txids {
    use super::*;
    pub fn deserialize<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Vec<Txid>, D::Error> {
        Vec::<String>::deserialize(d)?
            .into_iter()
            .map(|v| {
                v.parse()
                    .map_err(|_| serde::de::Error::custom("invalid RPC txid"))
            })
            .collect()
    }
}

#[derive(Clone, Debug, Deserialize)]
pub struct BlockchainInfo {
    pub chain: String,
    pub blocks: u64,
    pub headers: u64,
    #[serde(with = "hash")]
    pub bestblockhash: BlockHash,
    pub difficulty: JsonNumber,
    pub verificationprogress: JsonNumber,
    pub chainwork: String,
    pub pruned: bool,
    #[serde(default)]
    pub pruneheight: Option<u64>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct BlockHeader {
    #[serde(with = "hash")]
    pub hash: BlockHash,
    /// -1 means stale, not active-chain inclusion.
    pub confirmations: i64,
    pub height: u64,
    pub version: i32,
    #[serde(with = "hash")]
    pub merkleroot: MerkleRoot,
    pub time: u64,
    #[serde(default)]
    pub mediantime: Option<u64>,
    pub nonce: u32,
    pub bits: String,
    pub difficulty: JsonNumber,
    pub chainwork: String,
    #[serde(default, deserialize_with = "optional_hash::deserialize")]
    pub previousblockhash: Option<BlockHash>,
    #[serde(default, deserialize_with = "optional_hash::deserialize")]
    pub nextblockhash: Option<BlockHash>,
}

/// Verbosity 1: txids only. This DTO cannot be converted into a serialized block.
#[derive(Clone, Debug)]
pub struct BlockInfo {
    pub header: BlockHeader,
    pub size: u64,
    pub tx: Vec<Txid>,
}
impl<'de> Deserialize<'de> for BlockInfo {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let (header, tail) = deserialize_block::<_, RpcTxid>(d)?;
        Ok(Self {
            header,
            size: tail.size,
            tx: tail.tx.into_iter().map(|id| id.0).collect(),
        })
    }
}

/// A block observation with the transaction representation selected by the request.
/// This DTO does not reconstruct signed wire bytes from verbose JSON.
#[derive(Clone, Debug)]
pub struct Block {
    pub header: BlockHeader,
    pub size: u64,
    pub transactions: BlockTransactions,
}
impl Block {
    /// Decode a verbosity-2 response, retaining `Full` even for an empty `tx` array.
    /// A separate decoder is required because JSON alone cannot distinguish empty modes.
    pub fn deserialize_full<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let (header, tail) = deserialize_block(d)?;
        Ok(Self {
            header,
            size: tail.size,
            transactions: BlockTransactions::Full(tail.tx),
        })
    }
}
impl From<BlockInfo> for Block {
    fn from(info: BlockInfo) -> Self {
        Self {
            header: info.header,
            size: info.size,
            transactions: BlockTransactions::Hashes(info.tx),
        }
    }
}

/// Ordered transaction hashes or full transaction observations, as requested.
#[derive(Clone, Debug)]
pub enum BlockTransactions {
    Hashes(Vec<Txid>),
    Full(Vec<BlockTransaction>),
}
impl BlockTransactions {
    pub fn as_hashes(&self) -> Option<&[Txid]> {
        match self {
            Self::Hashes(hashes) => Some(hashes),
            Self::Full(_) => None,
        }
    }
    pub fn as_transactions(&self) -> Option<&[BlockTransaction]> {
        match self {
            Self::Full(transactions) => Some(transactions),
            Self::Hashes(_) => None,
        }
    }
    pub fn len(&self) -> usize {
        match self {
            Self::Hashes(hashes) => hashes.len(),
            Self::Full(transactions) => transactions.len(),
        }
    }
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[derive(Deserialize)]
struct BlockFields<T> {
    size: u64,
    tx: Vec<T>,
}
fn deserialize_block<'de, D, T>(d: D) -> Result<(BlockHeader, BlockFields<T>), D::Error>
where
    D: serde::Deserializer<'de>,
    T: serde::de::DeserializeOwned,
{
    // serde flatten's intermediate Value loses raw numeric tokens. Parse both views
    // directly from the same original JSON instead, for either verbosity.
    let raw = alloc::boxed::Box::<serde_json::value::RawValue>::deserialize(d)?;
    let header = serde_json::from_str(raw.get()).map_err(serde::de::Error::custom)?;
    let tail = serde_json::from_str(raw.get()).map_err(serde::de::Error::custom)?;
    Ok((header, tail))
}

#[derive(Clone, Debug, Deserialize)]
pub struct ScriptPubKey {
    pub asm: String,
    pub hex: String,
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(default, rename = "reqSigs")]
    pub required_signatures: Option<u32>,
    #[serde(default)]
    pub addresses: Vec<String>,
}

/// `gettxout` result. A null response is an observation of absence, not proof of a spend.
#[derive(Clone, Debug, Deserialize)]
pub struct TxOut {
    #[serde(with = "hash")]
    pub bestblock: BlockHash,
    pub confirmations: u64,
    pub value: RpcAmount,
    #[serde(rename = "scriptPubKey")]
    pub script_pub_key: ScriptPubKey,
    pub version: i32,
    pub coinbase: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SpendView {
    ConfirmedOnly,
    IncludeMempool,
}
impl SpendView {
    pub const fn include_mempool(self) -> bool {
        matches!(self, Self::IncludeMempool)
    }
}

#[derive(Clone, Debug, Deserialize)]
pub struct MempoolInfo {
    pub size: u64,
    pub bytes: u64,
    pub usage: u64,
    #[serde(default)]
    pub maxmempool: Option<u64>,
    #[serde(default)]
    pub mempoolminfee: Option<RpcAmount>,
}

/// Core's legacy boolean verbosity is explicit configuration, never an automatic replay.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum BlockVerbosity {
    #[default]
    Numeric,
    LegacyBoolean,
}

/// Useful for typed single-hash results without requiring serde on primitives.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(transparent)]
pub struct RpcBlockHash(#[serde(with = "hash")] pub BlockHash);
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(transparent)]
pub struct RpcTxid(#[serde(with = "hash")] pub Txid);

#[derive(Clone, Debug, Deserialize)]
pub struct NetworkInfo {
    pub version: u64,
    pub subversion: String,
    pub protocolversion: u64,
    pub connections: u64,
    pub relayfee: RpcAmount,
    #[serde(default)]
    pub localrelay: Option<bool>,
    #[serde(default)]
    pub networkactive: Option<bool>,
}
#[derive(Clone, Debug, Deserialize)]
pub struct ChainTip {
    pub height: u64,
    #[serde(with = "hash")]
    pub hash: BlockHash,
    pub branchlen: u64,
    pub status: String,
}
#[derive(Clone, Debug, Deserialize)]
pub struct TransactionOutput {
    pub value: RpcAmount,
    pub n: u32,
    #[serde(rename = "scriptPubKey")]
    pub script_pub_key: ScriptPubKey,
}

/// Core's block transaction observation. `hex` and `weight` may be absent.
#[derive(Clone, Debug, Deserialize)]
pub struct BlockTransaction {
    #[serde(with = "hash")]
    pub txid: Txid,
    /// Core's `GetWitnessHash`, retained independently of `txid`, not recomputed.
    /// Its bytes equal `txid` for transactions without witness data.
    #[serde(with = "hash")]
    pub hash: Wtxid,
    pub size: u64,
    pub vsize: u64,
    #[serde(default)]
    pub weight: Option<u64>,
    pub version: i32,
    pub locktime: u32,
    pub vin: Vec<TransactionInput>,
    pub vout: Vec<TransactionOutput>,
    #[serde(default)]
    pub hex: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct ScriptSig {
    pub asm: String,
    pub hex: String,
}

/// An input has exactly one category; a spend always has a complete typed outpoint.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TransactionInputKind {
    Coinbase { coinbase: String },
    Spend { txid: Txid, vout: u32 },
}

#[derive(Clone, Debug)]
pub struct TransactionInput {
    pub kind: TransactionInputKind,
    pub sequence: u32,
    pub script_sig: Option<ScriptSig>,
    /// Witness stack in Core's order, when reported (including an explicitly empty stack).
    pub txinwitness: Option<Vec<String>>,
}
impl<'de> Deserialize<'de> for TransactionInput {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        // Missing discriminating fields are allowed, but explicit null is not a category
        // and must not hide a mixed coinbase/outpoint or incomplete spend.
        fn present<'de, D: serde::Deserializer<'de>, T: Deserialize<'de>>(
            d: D,
        ) -> Result<Option<T>, D::Error> {
            T::deserialize(d).map(Some)
        }
        #[derive(Deserialize)]
        struct Fields {
            #[serde(default, deserialize_with = "present")]
            coinbase: Option<String>,
            #[serde(default, deserialize_with = "present")]
            txid: Option<RpcTxid>,
            #[serde(default, deserialize_with = "present")]
            vout: Option<u32>,
            sequence: u32,
            #[serde(default, rename = "scriptSig")]
            script_sig: Option<ScriptSig>,
            #[serde(default)]
            txinwitness: Option<Vec<String>>,
        }
        let fields = Fields::deserialize(d)?;
        let kind = match (fields.coinbase, fields.txid, fields.vout) {
            (Some(coinbase), None, None) => TransactionInputKind::Coinbase { coinbase },
            (None, Some(txid), Some(vout)) => TransactionInputKind::Spend { txid: txid.0, vout },
            _ => {
                return Err(serde::de::Error::custom(
                    "input requires either coinbase or both txid and vout, without mixing them",
                ));
            }
        };
        Ok(Self {
            kind,
            sequence: fields.sequence,
            script_sig: fields.script_sig,
            txinwitness: fields.txinwitness,
        })
    }
}

/// A verbose transaction is a DTO, not a reconstruction of signed wire bytes.
#[derive(Clone, Debug, Deserialize)]
pub struct TransactionInfo {
    #[serde(with = "hash")]
    pub txid: Txid,
    #[serde(default)]
    pub hex: Option<String>,
    pub version: i32,
    pub locktime: u32,
    pub vout: Vec<TransactionOutput>,
    #[serde(default, deserialize_with = "optional_hash::deserialize")]
    pub blockhash: Option<BlockHash>,
    #[serde(default)]
    pub confirmations: Option<i64>,
    #[serde(default)]
    pub time: Option<u64>,
    #[serde(default)]
    pub blocktime: Option<u64>,
}
#[derive(Clone, Debug, Deserialize)]
pub struct MempoolEntry {
    pub size: u64,
    pub fee: RpcAmount,
    #[serde(default)]
    pub modifiedfee: Option<RpcAmount>,
    pub time: u64,
    pub height: u64,
    #[serde(default)]
    pub descendantcount: Option<u64>,
    #[serde(default)]
    pub descendantsize: Option<u64>,
    #[serde(default, deserialize_with = "txids::deserialize")]
    pub depends: Vec<Txid>,
}

pub mod wallet;

#[cfg(test)]
mod tests {
    use super::*;

    const ID: &str = "5fd1843277d6785d2f0aabc5134275a08c0438033889270ed97b4cc0d0f7a1d1";
    const OTHER: &str = "91ad35ec9a22b3d1c451fea8523c4152eb875f2b6543ca573ba685af9d1949df";

    #[test]
    fn full_transaction_preserves_reported_hash_optional_fields_and_order() {
        let text = alloc::format!(
            r#"{{"txid":"{ID}","hash":"{OTHER}","size":200,"vsize":150,"weight":600,
            "version":2,"locktime":9,"hex":"0102",
            "vin":[
              {{"txid":"{OTHER}","vout":3,"sequence":7,"scriptSig":{{"asm":"sig","hex":"ab"}},"txinwitness":["bb","aa"]}},
              {{"txid":"{ID}","vout":1,"sequence":8,"txinwitness":[]}}
            ],
            "vout":[
              {{"n":4,"value":90071992.54740993,"scriptPubKey":{{"asm":"","hex":"51","type":"nonstandard"}}}},
              {{"n":2,"value":1e-8,"scriptPubKey":{{"asm":"","hex":"52","type":"nonstandard"}}}}
            ]}}"#
        );
        let tx: BlockTransaction = serde_json::from_str(&text).unwrap();
        assert_eq!(tx.txid, ID.parse().unwrap());
        // Synthetic independent IDs check preservation, not consistency with optional hex.
        assert_eq!(tx.hash, Wtxid::from_rpc_hex(OTHER).unwrap());
        assert_eq!(tx.weight, Some(600));
        assert_eq!(tx.hex.as_deref(), Some("0102"));
        for (input, id, vout, sequence) in [(&tx.vin[0], OTHER, 3, 7), (&tx.vin[1], ID, 1, 8)] {
            assert_eq!(
                input.kind,
                TransactionInputKind::Spend {
                    txid: id.parse().unwrap(),
                    vout
                }
            );
            assert_eq!(input.sequence, sequence);
        }
        assert_eq!(tx.vin[0].script_sig.as_ref().unwrap().hex, "ab");
        assert!(tx.vin[1].script_sig.is_none());
        assert_eq!(tx.vin[0].txinwitness.as_deref().unwrap(), &["bb", "aa"]);
        assert!(tx.vin[1].txinwitness.as_ref().unwrap().is_empty());
        assert_eq!(tx.vout[0].n, 4);
        assert_eq!(tx.vout[1].n, 2);
        assert_eq!(tx.vout[0].value.koinu(), 9_007_199_254_740_993);
        assert_eq!(tx.vout[0].value.source_text(), "90071992.54740993");
        assert_eq!(tx.vout[1].value.koinu(), 1);
        assert_eq!(tx.vout[1].value.source_text(), "1e-8");
    }

    #[test]
    fn rejects_ambiguous_or_incomplete_input_categories() {
        for fields in [
            String::new(),
            alloc::format!(r#""txid":"{ID}","#),
            String::from(r#""vout":1,"#),
            alloc::format!(r#""coinbase":"00","txid":"{ID}","#),
            String::from(r#""coinbase":"00","vout":1,"#),
            alloc::format!(r#""coinbase":"00","txid":"{ID}","vout":1,"#),
            String::from(r#""coinbase":"00","txid":null,"#),
            String::from(r#""coinbase":"00","vout":null,"#),
            alloc::format!(r#""txid":"{ID}","vout":null,"#),
            String::from(r#""coinbase":null,"#),
            String::from(r#""txid":"not-a-txid","vout":0,"#),
            alloc::format!(r#""txid":"{ID}","vout":4294967296,"#),
            String::from(r#""coinbase":"00","coinbase":"01","#),
        ] {
            let text = alloc::format!(r#"{{{fields}"sequence":4294967295}}"#);
            assert!(
                serde_json::from_str::<TransactionInput>(&text).is_err(),
                "{text}"
            );
        }
    }
}
