//! Watch-only Dogecoin Core wallet RPC contracts; no private keys or signing.
use super::*;
use core::str::FromStr;

/// Signed wallet delta/fee, in exact integer koinu, retaining the JSON token.
/// In contrast to an output amount, a wallet debit or fee may be negative.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RpcSignedAmount {
    source: JsonNumber,
    koinu: i64,
}
impl RpcSignedAmount {
    pub fn koinu(&self) -> i64 {
        self.koinu
    }
    pub fn source_text(&self) -> &str {
        self.source.as_str()
    }
}
impl FromStr for RpcSignedAmount {
    type Err = AmountError;
    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let source: JsonNumber = text.parse()?;
        let text = source.as_str();
        let (negative, magnitude) = match text.strip_prefix('-') {
            Some(magnitude) => (true, magnitude),
            None => (false, text),
        };
        let value = planchet_primitives::Amount::from_doge_str(magnitude)?.to_koinu();
        let signed = if negative {
            -(value as i128)
        } else {
            value as i128
        };
        let koinu = i64::try_from(signed).map_err(|_| AmountError::Overflow)?;
        Ok(Self { source, koinu })
    }
}
impl<'de> Deserialize<'de> for RpcSignedAmount {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let number = JsonNumber::deserialize(d)?;
        number.as_str().parse().map_err(serde::de::Error::custom)
    }
}
impl Serialize for RpcSignedAmount {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        self.source.serialize(s)
    }
}

#[derive(Clone, Debug, Deserialize)]
pub struct Unspent {
    #[serde(with = "hash")]
    pub txid: Txid,
    pub vout: u32,
    #[serde(default)]
    pub address: Option<String>,
    #[serde(default)]
    pub account: Option<String>,
    #[serde(rename = "scriptPubKey")]
    pub script_pub_key: String,
    pub amount: RpcAmount,
    pub confirmations: u64,
    pub spendable: bool,
    #[serde(default)]
    pub solvable: Option<bool>,
    #[serde(default, rename = "redeemScript")]
    pub redeem_script: Option<String>,
}
#[derive(Clone, Debug, Deserialize)]
pub struct AddressInfo {
    pub isvalid: bool,
    #[serde(default)]
    pub address: Option<String>,
    #[serde(default)]
    pub ismine: Option<bool>,
    #[serde(default)]
    pub iswatchonly: Option<bool>,
    #[serde(default, rename = "scriptPubKey")]
    pub script_pub_key: Option<String>,
    #[serde(default)]
    pub isscript: Option<bool>,
    #[serde(default)]
    pub timestamp: Option<u64>,
    #[serde(default)]
    pub account: Option<String>,
}
#[derive(Clone, Debug, Serialize)]
#[serde(untagged)]
pub enum ImportScript {
    Address { address: String },
    Hex(String),
}
#[derive(Clone, Debug)]
pub enum ImportTimestamp {
    Now,
    Unix(u64),
}
impl Serialize for ImportTimestamp {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Now => s.serialize_str("now"),
            Self::Unix(time) => s.serialize_u64(*time),
        }
    }
}
#[derive(Clone, Debug, Serialize)]
pub struct WatchImport {
    #[serde(rename = "scriptPubKey")]
    pub script_pub_key: ImportScript,
    pub timestamp: ImportTimestamp,
    pub watchonly: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redeemscript: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pubkeys: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub internal: Option<bool>,
}
impl WatchImport {
    /// No private-key field exists on this watch-only request.
    pub fn address(address: impl Into<String>, timestamp: ImportTimestamp) -> Self {
        Self {
            script_pub_key: ImportScript::Address {
                address: address.into(),
            },
            timestamp,
            watchonly: true,
            label: None,
            redeemscript: None,
            pubkeys: None,
            internal: None,
        }
    }
}
#[derive(Clone, Debug, Deserialize)]
pub struct ImportError {
    pub code: i64,
    pub message: String,
}
#[derive(Clone, Debug, Deserialize)]
pub struct ImportResult {
    pub success: bool,
    #[serde(default)]
    pub error: Option<ImportError>,
    #[serde(default)]
    pub warnings: Vec<String>,
}

/// `listtransactions`/`listsinceblock` entry. Legacy accounting `move` entries
/// have no transaction ID or chain confirmation data. Conflicts may be negative.
#[derive(Clone, Debug, Deserialize)]
pub struct WalletTransactionEntry {
    #[serde(default, deserialize_with = "optional_txid")]
    pub txid: Option<Txid>,
    pub category: String,
    pub amount: RpcSignedAmount,
    #[serde(default)]
    pub fee: Option<RpcSignedAmount>,
    #[serde(default)]
    pub address: Option<String>,
    #[serde(default)]
    pub account: Option<String>,
    #[serde(default)]
    pub label: Option<String>,
    #[serde(default)]
    pub vout: Option<u32>,
    #[serde(default)]
    pub confirmations: Option<i64>,
    #[serde(default, deserialize_with = "super::optional_hash::deserialize")]
    pub blockhash: Option<BlockHash>,
    #[serde(default)]
    pub blockindex: Option<u32>,
    #[serde(default)]
    pub blocktime: Option<u64>,
    #[serde(default)]
    pub time: Option<u64>,
    #[serde(default)]
    pub timereceived: Option<u64>,
    #[serde(default)]
    pub trusted: Option<bool>,
    #[serde(default)]
    pub generated: Option<bool>,
    #[serde(default)]
    pub abandoned: Option<bool>,
    #[serde(default, rename = "involvesWatchonly")]
    pub involves_watchonly: Option<bool>,
    #[serde(default, rename = "bip125-replaceable")]
    pub bip125_replaceable: Option<String>,
    #[serde(default, deserialize_with = "super::txids::deserialize")]
    pub walletconflicts: Vec<Txid>,
    #[serde(default)]
    pub otheraccount: Option<String>,
    #[serde(default)]
    pub comment: Option<String>,
}

fn optional_txid<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<Txid>, D::Error> {
    Option::<String>::deserialize(d)?
        .map(|v| {
            v.parse()
                .map_err(|_| serde::de::Error::custom("invalid wallet txid"))
        })
        .transpose()
}

#[derive(Clone, Debug, Deserialize)]
pub struct ListSinceBlockResult {
    pub transactions: Vec<WalletTransactionEntry>,
    #[serde(with = "hash")]
    pub lastblock: BlockHash,
    /// Some newer compatible nodes include removed entries; 1.14.x may omit it.
    #[serde(default)]
    pub removed: Vec<WalletTransactionEntry>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct ReceivedByAddress {
    pub address: String,
    pub amount: RpcAmount,
    pub confirmations: u64,
    #[serde(deserialize_with = "super::txids::deserialize")]
    pub txids: Vec<Txid>,
    #[serde(default)]
    pub account: Option<String>,
    #[serde(default)]
    pub label: Option<String>,
    #[serde(default, rename = "involvesWatchonly")]
    pub involves_watchonly: Option<bool>,
}

/// Absence of `scanning` on Dogecoin 1.14.x is unknown, not proof of completion.
#[derive(Clone, Debug)]
pub enum WalletScanning {
    Flag(bool),
    Progress { duration: u64, progress: JsonNumber },
}
impl<'de> Deserialize<'de> for WalletScanning {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        // Avoid serde's untagged intermediate representation, which loses raw numbers.
        let raw = alloc::boxed::Box::<serde_json::value::RawValue>::deserialize(d)?;
        if let Ok(flag) = serde_json::from_str::<bool>(raw.get()) {
            return Ok(Self::Flag(flag));
        }
        #[derive(Deserialize)]
        struct Progress {
            duration: u64,
            progress: JsonNumber,
        }
        let p: Progress = serde_json::from_str(raw.get()).map_err(serde::de::Error::custom)?;
        Ok(Self::Progress {
            duration: p.duration,
            progress: p.progress,
        })
    }
}

#[derive(Clone, Debug, Deserialize)]
pub struct WalletInfo {
    pub walletversion: u64,
    pub balance: RpcSignedAmount,
    pub unconfirmed_balance: RpcSignedAmount,
    pub immature_balance: RpcSignedAmount,
    pub txcount: u64,
    pub keypoololdest: u64,
    pub keypoolsize: u64,
    pub paytxfee: RpcAmount,
    #[serde(default)]
    pub unlocked_until: Option<u64>,
    #[serde(default)]
    pub hdmasterkeyid: Option<String>,
    #[serde(default)]
    pub watchonly_balance: Option<RpcSignedAmount>,
    #[serde(default)]
    pub unconfirmed_watchonly_balance: Option<RpcSignedAmount>,
    #[serde(default)]
    pub immature_watchonly_balance: Option<RpcSignedAmount>,
    #[serde(default)]
    pub scanning: Option<WalletScanning>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct RescanWalletState {
    pub balance: RpcSignedAmount,
    pub txcount: u64,
}

/// Dogecoin's `rescan` result, not Bitcoin's `rescanblockchain` response.
#[derive(Clone, Debug, Deserialize)]
pub struct RescanResult {
    pub before: RescanWalletState,
    pub after: RescanWalletState,
    pub blocks_scanned: u64,
    pub time_elapsed: JsonNumber,
}
