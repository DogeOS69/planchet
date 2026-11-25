//! Typed watch-only wallet RPC. Every mutation sends exactly one request, with
//! no retry, fallback import, rescan polling, or assumption of rollback on error.
//! A timeout may occur after a mutation took effect; the caller must reconcile.
use crate::{Error, Provider, types::wallet::*};
use planchet_primitives::BlockHash;
use planchet_transport::Transport;

/// Core's indexer needs all positive UTXOs, including dust. This separate budget
/// does not change the ordinary client's 64 MiB budget. Configure the transport
/// ceiling separately; a 1 GiB body can require several GiB of decoding memory.
pub const MAX_LISTUNSPENT_RESPONSE_BYTES: usize = 1024 * 1024 * 1024;
pub const LIST_UNSPENT_MAXCONF: u64 = i32::MAX as u64;

/// Both caps fail the whole response. No partial/truncated snapshot is returned.
/// The default has no extra count restriction beyond the 1 GiB body budget.
#[derive(Clone, Copy, Debug)]
pub struct SnapshotLimits {
    pub max_response_bytes: usize,
    pub max_entries: usize,
}
impl Default for SnapshotLimits {
    fn default() -> Self {
        Self {
            max_response_bytes: MAX_LISTUNSPENT_RESPONSE_BYTES,
            max_entries: usize::MAX,
        }
    }
}

/// Entire `listunspent` result relative to the recorded wallet/filter at the
/// time the node answered. Not a chain-anchored proof or a UTXO spend assertion.
#[derive(Clone, Debug)]
pub struct UnspentSnapshot {
    pub min_confirmations: u64,
    pub max_confirmations: u64,
    pub addresses: Vec<String>,
    pub include_unsafe: bool,
    pub outputs: Vec<Unspent>,
}

impl<T: Transport> Provider<T> {
    pub async fn validate_address(&self, address: &str) -> Result<AddressInfo, Error> {
        self.client().call("validateaddress", [address]).await
    }

    /// Import an address or hex script once. `rescan` and P2SH wrapping are
    /// explicit; Dogecoin accepts an optional fifth rescan-start height.
    pub async fn import_address(
        &self,
        address_or_hex: &str,
        label: Option<&str>,
        rescan: bool,
        p2sh: bool,
        height: Option<u64>,
    ) -> Result<(), Error> {
        match height {
            Some(height) => {
                self.client()
                    .call(
                        "importaddress",
                        (address_or_hex, label.unwrap_or(""), rescan, p2sh, height),
                    )
                    .await
            }
            None => {
                self.client()
                    .call(
                        "importaddress",
                        (address_or_hex, label.unwrap_or(""), rescan, p2sh),
                    )
                    .await
            }
        }
    }

    /// Preserve request order, per-result warnings, and individual Core errors.
    /// Partial failure is returned as data, never retried with another import.
    pub async fn import_multi(
        &self,
        requests: &[WatchImport],
        rescan: bool,
    ) -> Result<Vec<ImportResult>, Error> {
        if requests.iter().any(|request| !request.watchonly) {
            return Err(invalid(
                "importmulti",
                "watch-only imports require watchonly=true",
            ));
        }
        #[derive(serde::Serialize)]
        struct Options {
            rescan: bool,
        }
        let results: Vec<ImportResult> = self
            .client()
            .call("importmulti", (requests, Options { rescan }))
            .await?;
        if results.len() != requests.len() || results.iter().any(|r| r.success == r.error.is_some())
        {
            return Err(invalid(
                "importmulti",
                "inconsistent per-request import results",
            ));
        }
        Ok(results)
    }

    /// The three positional arguments used by core's anchored wallet scanner.
    /// A null hash asks Core for history without a start marker.
    pub async fn list_since_block(
        &self,
        blockhash: Option<BlockHash>,
        target_confirmations: u64,
        include_watchonly: bool,
    ) -> Result<ListSinceBlockResult, Error> {
        self.client()
            .call(
                "listsinceblock",
                (
                    blockhash.map(|hash| hash.to_string()),
                    target_confirmations,
                    include_watchonly,
                ),
            )
            .await
    }

    pub async fn list_received_by_address(
        &self,
        min_confirmations: u64,
        include_empty: bool,
        include_watchonly: bool,
    ) -> Result<Vec<ReceivedByAddress>, Error> {
        self.client()
            .call(
                "listreceivedbyaddress",
                (min_confirmations, include_empty, include_watchonly),
            )
            .await
    }

    /// A single page only. No automatic pagination or deduplication; negative
    /// amounts, fees and conflicted confirmations retain their signed values.
    pub async fn list_transactions(
        &self,
        account: &str,
        count: u64,
        skip: u64,
        include_watchonly: bool,
    ) -> Result<Vec<WalletTransactionEntry>, Error> {
        let entries: Vec<WalletTransactionEntry> = self
            .client()
            .call(
                "listtransactions",
                (account, count, skip, include_watchonly),
            )
            .await?;
        if entries.len() as u64 > count {
            return Err(invalid(
                "listtransactions",
                "node returned more entries than requested",
            ));
        }
        Ok(entries)
    }

    /// Complete snapshot including unsafe outputs, as used for core indexer
    /// reconciliation. No minimum-amount, maximum-count or sum truncation query.
    pub async fn list_unspent(
        &self,
        min_confirmations: u64,
        max_confirmations: u64,
        addresses: &[String],
        limits: SnapshotLimits,
    ) -> Result<UnspentSnapshot, Error> {
        self.list_unspent_with_unsafe(
            min_confirmations,
            max_confirmations,
            addresses,
            true,
            limits,
        )
        .await
    }

    pub async fn list_unspent_with_unsafe(
        &self,
        min_confirmations: u64,
        max_confirmations: u64,
        addresses: &[String],
        include_unsafe: bool,
        limits: SnapshotLimits,
    ) -> Result<UnspentSnapshot, Error> {
        if min_confirmations > max_confirmations || max_confirmations > LIST_UNSPENT_MAXCONF {
            return Err(invalid(
                "listunspent",
                "invalid confirmation range (Core uses signed 32-bit counts)",
            ));
        }
        if limits.max_entries == 0
            || limits.max_response_bytes == 0
            || limits.max_response_bytes > MAX_LISTUNSPENT_RESPONSE_BYTES
        {
            return Err(invalid(
                "listunspent",
                "snapshot requires a positive entry/byte cap, at most 1 GiB",
            ));
        }
        let raw: Box<serde_json::value::RawValue> = self
            .client()
            .call_with_response_limit(
                "listunspent",
                (
                    min_confirmations,
                    max_confirmations,
                    addresses,
                    include_unsafe,
                ),
                limits.max_response_bytes,
            )
            .await?;
        // Bound entries while decoding, not after materializing the whole list.
        use serde::de::{DeserializeSeed, IgnoredAny, SeqAccess, Visitor};
        struct Capped(usize);
        impl<'de> DeserializeSeed<'de> for Capped {
            type Value = Vec<Unspent>;
            fn deserialize<D: serde::Deserializer<'de>>(
                self,
                d: D,
            ) -> Result<Self::Value, D::Error> {
                d.deserialize_seq(self)
            }
        }
        impl<'de> Visitor<'de> for Capped {
            type Value = Vec<Unspent>;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("bounded complete unspent list")
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
                let mut values = Vec::new();
                loop {
                    if values.len() == self.0 {
                        if seq.next_element::<IgnoredAny>()?.is_some() {
                            return Err(serde::de::Error::custom("snapshot entry cap exceeded"));
                        }
                        break;
                    }
                    match seq.next_element::<Unspent>()? {
                        Some(value) => values.push(value),
                        None => break,
                    }
                }
                Ok(values)
            }
        }
        let mut deserializer = serde_json::Deserializer::from_str(raw.get());
        let outputs = Capped(limits.max_entries)
            .deserialize(&mut deserializer)
            .map_err(|_| invalid("listunspent", "invalid or oversized complete snapshot"))?;
        deserializer
            .end()
            .map_err(|_| invalid("listunspent", "trailing snapshot data"))?;
        Ok(UnspentSnapshot {
            min_confirmations,
            max_confirmations,
            addresses: addresses.to_vec(),
            include_unsafe,
            outputs,
        })
    }

    /// Wallet-disabled/node errors propagate. A missing scanning field remains
    /// unknown; this method never infers that a concurrent rescan completed.
    pub async fn wallet_info(&self) -> Result<WalletInfo, Error> {
        self.client().call("getwalletinfo", [] as [u8; 0]).await
    }

    /// Dogecoin 1.14.x `rescan`, supported only by non-pruned wallets. The
    /// caller configures a suitably long transport deadline. No fallback to
    /// Bitcoin's `rescanblockchain`, no polling/replay on timeout or node error.
    pub async fn rescan(&self, height: u64) -> Result<RescanResult, Error> {
        self.client().call("rescan", [height]).await
    }
}

fn invalid(method: &str, reason: &'static str) -> Error {
    Error::InvalidResponse {
        method: method.into(),
        reason,
    }
}
