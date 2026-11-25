# planchet-consensus

Rust 2024, **MSRV 1.91**. Project release license pending. Dependencies use Rust
cryptographic implementations; SHA-256 selects the software backend. No C
cryptography, native build dependency, or nintondo dependency is used. Upstream
`sha2 0.10` still declares `cpufeatures` and, on some targets, Rust `libc`
bindings even with `force-soft`; these are visible in Cargo's dependency graph.

## Features

| Configuration | Available functionality |
| --- | --- |
| `default-features = false` | `no_std`, no allocator: CompactSize, borrowed transactions/headers/blocks, SHA256d IDs, checked whole-block Merkle roots, Script reading, inclusion/proof reading |
| `alloc` (default) | Also expose `transaction` and `sighash` modules for owned transactions and offline signing |
| `std` | Implies `alloc`, forwards primitives' `std` feature |
| `pow-scrypt` | Optional native scrypt tools, implies `alloc`; does not validate AuxPoW mining commitments |

The fixed-stack Merkle calculator does not allocate a transaction-count-sized
vector. Borrowed decoders never allocate. Iterators re-read validated bytes,
retain block/transaction order, and implement `ExactSizeIterator` and
`FusedIterator`. Limits do not become capacities or reservations.

## Borrowed API

```rust
use planchet_consensus::{BlockRef, DecodeLimits};

fn inspect(raw_block: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    let block = BlockRef::decode_exact(raw_block, DecodeLimits::default())?;
    let block_id = block.header().block_id(); // SHA256d child-header ID
    block.check_tx_merkle_root()?;
    for (tx, txid) in block.transactions().zip(block.txids()) {
        for out in tx.outputs() {
            let value_bits = out.value(); // unsigned wire bits, not Amount validation
            let script = out.script_pubkey();
            let range = out.script_pubkey_range(); // relative to tx.bytes()
            assert_eq!(script, &tx.bytes()[range]);
        }
    }
    Ok(())
}
```

- `TxRef::decode_exact(bytes, limits)` rejects trailing bytes;
  `decode_prefix` returns `(TxRef, consumed_bytes)`. A prefix budget covers only
  the consumed transaction, so a block suffix may exceed `max_tx_bytes`.
- `bytes`, `version`, `version_bits`, `lock_time`, `input_count`, `output_count`,
  `inputs`, `outputs`, `is_coinbase`, and `txid` provide borrowed inspection.
  Transaction `version` is signed `i32`; `version_bits` retains its `u32` bits.
- Input accessors: `bytes`, `previous_txid`, `vout`, `script_sig`,
  `script_sig_range`, `sequence`, `is_coinbase` (null outpoint). Output accessors:
  `bytes`, `value`, `value_wire_bytes`, `script_pubkey`, `script_pubkey_range`.
  Script ranges exclude the length prefix and are relative to the original
  transaction, including for a parent coinbase's own `bytes()`.
- Native transactions require a nonempty input vector, allow zero outputs at
  the structural layer, reject witness encoding, and hash **the signed raw wire
  bytes** for `Txid`. Script pushes are never normalized. Negative output bits
  remain readable; monetary and script validation are separate operations.
- `TxRef::decode_unsigned_exact` is the explicit PSBT/non-witness mode. It
  permits empty inputs and always interprets the next byte as the legacy output
  count, never as a witness flag. PSBT's empty-scriptSig rule is checked by the
  PSBT layer. This mode is not used for block transactions or AuxPoW parents.
- CompactSize rejects nonminimal encodings and values over explicit maxima.
  Every vector count, script, transaction, block, header, parent transaction,
  branch, and witness has an explicit budget. Counts are also checked against
  the minimum bytes required before iteration. `DecodeLimits::default()` is an
  application profile, not a declaration of Dogecoin consensus limits.

## Headers, AuxPoW, and Merkle roots

`BaseHeader` has public native fields: `version`, `prev_blockhash`,
`merkle_root`, `time`, `bits`, `nonce`. `encode()` always returns 80 bytes;
`block_id()` returns `planchet_primitives::BlockHash`, including when the
version flags AuxPoW. It does not compute a scrypt PoW hash.

`WireHeader::{decode_exact,decode_prefix}` require the complete AuxPoW trailer
when bit 8 is set. `base()` and `auxpow()` inspect it; `bytes()` retains the
original full header, and `encode_into()` serializes the native fields and
copies the validated auxiliary wire payload, including witness. An 80-byte
AuxPoW child prefix alone is a valid `BaseHeader`, not a complete `WireHeader`.

`AuxPowRef` exposes the parent `coinbase()`, retained `parent_block_hash()`,
`coinbase_branch()` / `coinbase_index()`, `chain_branch()` / `chain_index()`,
and `parent_header()`. Each branch borrows its hash bytes and has a fixed-width
`hashes()` iterator. Indices keep their signed `i32` wire bits. The parent
header is always 80 bytes even if its version happens to contain bit 8.

`ParentCoinbaseRef` requires exactly one null-outpoint input, permits zero
outputs (as Core's AuxPoW fixtures do), and accepts optional marker/flag `00 01`
encoding. Its witness items and serialized witness bytes are bounded and
borrowed; unknown flags are rejected. Core 1.14.9 accepts an empty encoded
witness stack, so this parser retains it too. The parent `txid()` excludes
marker, flag, and witness while `bytes()` retains them.

`BlockRef::txids()` yields ordered raw txids. `tx_merkle_root()` computes a
nonempty tree and rejects equal real siblings at any level. Odd-tail
duplication is permitted. `check_tx_merkle_root() -> Result<(), MerkleError>`
also compares against the header. Decoding alone does not run this check.

These types establish byte structure and resource limits. They do not establish
Script validity, amounts, valid PoW, difficulty adjustment, parent/child AuxPoW
commitments, chain identity, or canonical chain membership. Inclusion checking
alone cannot establish completeness or exclude mutations hidden in a supplied
subtree. See `inclusion` and `pow` module documentation for their contracts.

## Verification and provenance

```sh
cargo +1.91.0 test -p planchet-consensus --no-default-features
cargo +1.91.0 test -p planchet-consensus
cargo +1.91.0 test -p planchet-consensus --all-features
```

The byte fixtures and independent expected values are documented in
[`tests/fixtures/README.md`](tests/fixtures/README.md). The implementation was
written independently against [Dogecoin Core 1.14.9 serialization](https://github.com/dogecoin/dogecoin/tree/v1.14.9/src/primitives),
[AuxPoW layout](https://github.com/dogecoin/dogecoin/blob/v1.14.9/src/auxpow.h),
[CompactSize](https://github.com/dogecoin/dogecoin/blob/v1.14.9/src/serialize.h),
and [Merkle rules](https://github.com/dogecoin/dogecoin/blob/v1.14.9/src/consensus/merkle.cpp).
Core source is MIT licensed. No legacy Rust decoder or native dependency is
linked into tests; fixed data and independent expected values are used instead.
