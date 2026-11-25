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
integer parsing. BlockInfo parses header/tail views from the original raw JSON
because serde flatten's intermediate representation would lose raw numeric tokens.

The three number tests cover exact source-token round trips, scientific notation,
values beyond f64 integer precision, 1 koinu, u64::MAX and overflow, strict excess
precision, negative values, invalid JSON number forms and exponent bounds. Provider
HTTP tests exercise these DTOs through real response envelopes rather than only
serde in isolation. Wallet DTOs/tests are maintained with the wallet provider.
