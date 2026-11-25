//! Dogecoin Core RPC DTOs. Numeric tokens retain their source text; amounts never use floats.
#![no_std]
#![forbid(unsafe_code)]
extern crate alloc;

mod number;
use alloc::{string::String, vec::Vec};
pub use number::{AmountError, JsonNumber, RpcAmount};
use planchet_primitives::{BlockHash, MerkleRoot, Txid};
use serde::{Deserialize, Serialize};

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
        // serde flatten's intermediate Value loses raw numeric tokens. Parse both views
        // directly from the same original JSON instead.
        let raw = alloc::boxed::Box::<serde_json::value::RawValue>::deserialize(d)?;
        let header = serde_json::from_str(raw.get()).map_err(serde::de::Error::custom)?;
        #[derive(Deserialize)]
        struct Tail {
            size: u64,
            #[serde(deserialize_with = "txids::deserialize")]
            tx: Vec<Txid>,
        }
        let tail: Tail = serde_json::from_str(raw.get()).map_err(serde::de::Error::custom)?;
        Ok(Self {
            header,
            size: tail.size,
            tx: tail.tx,
        })
    }
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
