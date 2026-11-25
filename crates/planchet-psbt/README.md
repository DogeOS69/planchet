# planchet-psbt

`openvm-k256` routes SEC1 key validation and mathematical signature verification
through the shared `planchet-crypto` backend on RISC-V OpenVM guests. Other
targets use RustCrypto. Strict DER, low-S policy, template checks and atomic
PSBT updates are preserved.

BIP174 v0 ordered key/value maps and checked offline P2PKH payment operations.
Rust 2024, workspace MSRV 1.91. The default `alloc` feature enables the API;
without it the crate is an empty `no_std` shell. `alloc` itself needs no `std`.

## Codec and updates

`PsbtV0::decode(bytes, PsbtLimits)` bounds bytes, map entries and field lengths,
uses the common canonical CompactSize decoder, rejects duplicate keys, enforces
map counts from the unsigned transaction, and checks BIP174 v0 typed keys.
It delegates unsigned decoding to consensus's explicit no-witness parser.
Zero-input unsigned PSBTs are structurally supported; payment operations reject
them. Unsupported script/witness/extension values remain opaque.

`encode()` preserves map order and the exact field bytes, so an untouched valid
PSBT round trips byte-for-byte. `combine()` rejects different unsigned
transactions and conflicting values atomically. Compatible additions can change
encoding/order. Unknown fields in every map retain their original data.
Duplicate detection and combination use trees, without sorting wire records.

`insert_global`, `insert_input` and `insert_output` are explicit metadata updates
which cannot replace conflicting values. These do not authorize spending or
certify a partial/final signature. The unsigned transaction is immutable.

## Signing and extraction

1. Construct a consensus `Transaction`, preserving caller input/output order.
2. Create `PsbtV0::from_unsigned`, optionally `attach_parent` or
   `attach_compact_prevout`. Parent attachment recomputes txid and checks vout.
3. Call `sign_request(input, &trusted_prevouts, public_key, mode, budget)`.
   Trusted prevouts must cover every input in order. Full and compact embedded
   descriptions must agree with them. An absent embedded description is allowed
   because the public signing boundary still requires the explicit trusted data.
4. Obtain a DER signature over `request.digest()` using a prehash signer.
5. `insert_verified_signature(&request, public_key, der_without_mode, mode)`
   checks request freshness, intended key/mode, strict DER, low S and ECDSA before
   modifying the specified partial-signature field. It appends one mode byte.
6. Explicitly call `finalize_p2pkh(&trusted_prevouts, budget)` and/or
   `extract(&trusted_prevouts, budget)`. Both verify every P2PKH signature and the
   actual signed-size budget. Invalid final-script fields cannot bypass checks.

The request freezes unsigned bytes, all trusted prevouts, input, key, mode and
budget. Failed signature insertion/finalization leaves PSBT bytes unchanged.
Finalization clears BIP174 construction fields while retaining UTXOs, unknown
and proprietary records. `SignedPayment` provides the checked transaction,
serialization and `PaymentSummary`.

`PaymentBudget` checks nonnegative wire amounts, duplicate/null inputs, checked
input/output sums, coverage, maximum total fee and a minimum rate delegated to
the shared `FeeRate` ceiling calculation. Preflight conservatively budgets 139
scriptSig bytes per input (low-S DER plus an uncompressed key); extraction uses
actual signed bytes. A transaction that barely meets the rate with compressed
keys can therefore require a larger fee before authorization. The library never
adjusts change or clears signatures automatically to repair a budget.

Only exact legacy P2PKH is signed/finalized/extracted. P2SH, multisig, witness,
Taproot and arbitrary Script remain forwardable metadata. No Script VM, chain
membership/unspentness check, wallet selection, relay policy, node access or
broadcast is provided. The caller authenticates prevout origin and authorizes
the entire unsigned transaction and allowed metadata changes.

See the executable [`offline-p2pkh`](../planchet-signer/examples/offline-p2pkh.rs)
example and the signing crate's integration tests.
