# planchet-rpc-types

Dogecoin Core 1.14.9 JSON DTOs. Rust 2024, MSRV 1.91. Release license pending.
This crate uses no_std + alloc and has no default features.

`JsonNumber` preserves the validated JSON number token, including exponent and
trailing zeroes, using `serde_json::value::RawValue`. `RpcAmount` validates that
raw token with `planchet_primitives::Amount::from_doge_str`, exposes exact u64
koinu and the domain Amount, and serializes the original token. It never passes
through f64. Negative amounts, excess precision (including `0.0000000100`),
out-of-i32 exponents, and results beyond u64::MAX are rejected. JSON grammar
validation precedes the primitives' more permissive legacy decimal text parser.
Wallet signed values live in `wallet.rs` and have their own signed contract.

Hash fields use the primitives' canonical Display/FromStr boundary. Verbose
blocks with txids remain distinct from raw wire bytes; verbose transaction DTOs
never claim that missing signed bytes can be reconstructed. All decimal-valued
fields use exact amount or raw-number DTOs. Integer counters use checked serde
integer parsing. BlockInfo and the full block decoder share header/tail parsing
from the original raw JSON because serde flatten's intermediate representation
would lose raw numeric tokens.

`Block { header, size, transactions }` uses `BlockTransactions::Hashes(Vec<Txid>)`
or `Full(Vec<BlockTransaction>)`, with `as_hashes()`, `as_transactions()`, `len()`
and `is_empty()`. The provider selects the decoder from the requested mode;
`BlockInfo` decodes hashes and converts into `Block`, while
`Block::deserialize_full` decodes full transactions. Empty arrays retain their
requested variant. There is no shape-guessing `Deserialize` for `Block`.

`BlockTransaction` exposes `txid: Txid`, Core-reported `hash: Wtxid`,
`size`, `vsize`, optional `weight`, `version`, `locktime`, ordered `vin`/`vout`,
and optional `hex`. Outputs reuse `TransactionOutput` and `RpcAmount`.
`TransactionInput` has `kind`, `sequence`, optional `script_sig: ScriptSig`
(`asm`, `hex`), and optional `txinwitness: Vec<String>`. Its kind is
`TransactionInputKind::Coinbase { coinbase }` or `Spend { txid: Txid, vout: u32 }`.
Mixed coinbase/outpoint fields, incomplete outpoints, and explicit null category
fields are rejected. Core reports `hash` using `GetWitnessHash`; its bytes equal
`txid` for transactions without witness data. The fields remain independent;
neither is recomputed from optional hex. The synthetic DTO test deliberately uses
different IDs to check that both reported values are preserved.

The three number tests cover exact source-token round trips, scientific notation,
values beyond f64 integer precision, 1 koinu, u64::MAX and overflow, strict excess
precision, negative values, invalid JSON number forms and exponent bounds. Provider
HTTP tests exercise these DTOs through real response envelopes rather than only
serde in isolation. Wallet DTOs/tests are maintained with the wallet provider.
