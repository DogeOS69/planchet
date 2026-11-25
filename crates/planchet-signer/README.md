# planchet-signer

Prehashed secp256k1 ECDSA using pure Rust k256. Rust 2024, workspace MSRV 1.91,
`no_std` with allocation. There are no C crypto bindings, network clients or
entropy-source requirements in this crate's normal, dev or build dependencies.

`verify` exposes `PublicKey`, `EcdsaSignature`, `SignRequest`, `SignerResult`,
`DigestSigner`, `verify_prehash` and `verify_historical`. `local` adds
`LocalSigner`, with deterministic RFC6979 signing and zeroizing secret storage.
`psbt` adds `SignRequest::from_psbt`. Defaults are `local,psbt`; a verification
consumer should disable defaults and select `verify` (optionally `psbt`). k256's
shared `ecdsa` implementation feature includes its backend signing routines;
the verification profile exposes no `LocalSigner` API or randomness requirement.

`SignRequest::p2pkh` validates the exact template/key, all explicit trusted
prevouts and payment budget before computing the legacy digest. Its fields are
private. Alternatively convert an already checked PSBT request with
`SignRequest::from_psbt`. A `DigestSigner` adapter receives the typed 32-byte
digest. `LocalSigner::sign_prehash` uses `PrehashSigner`, without hashing again,
refuses a different expected key and emits strict DER, low S. Responses contain
DER without a mode byte, plus the intended mode and original SEC1 public key.
`SignRequest::validate_result` validates an external response; PSBT insertion
independently checks it again before any map change.

`EcdsaSignature::from_der` parses strict historical DER without rewriting it.
`verify_historical` accepts mathematically valid high-S signatures by normalizing
only a temporary scalar representation. `from_low_s_der` and `verify_prehash`
enforce current low-S policy. There is no lax pre-BIP66 parser or Script VM.
Consensus `legacy_sighash(tx, input, script_code, raw_type: u32)` preserves Core's
arbitrary hash bits and historical SINGLE/out-of-range digest-one semantics.
New `SighashType` accepts six defined modes; contextual requests reject SINGLE
without an output. Generic scriptCode callers must supply the context after the
last executed CODESEPARATOR and any required legacy signature FindAndDelete;
exact P2PKH needs neither operation.

## Offline example

```sh
cargo +1.91.0 run -p planchet-signer --example offline-p2pkh -- \
  parent.hex 0 DESTINATION_SCRIPT_HEX PAYMENT_KOINU MAX_FEE_KOINU MIN_RATE_KOINU_PER_KVB \
  < signing-key.hex > signed.hex
```

The parent is a full legacy transaction hex file, and the key file contains
exactly 32 hex-encoded secret bytes. The parent must already be authenticated
against the intended outpoint/chain by the caller. This one-input example makes
one explicit output: the remaining value is the fee, checked against both
budget limits. It signs offline, verifies finalization/extraction, writes raw
signed hex on stdout and an ID/size/fee summary on stderr. It never broadcasts.
No machine-specific paths, credentials or deployment keys are embedded.

## Independent checks

The local deterministic signature matches Dogecoin Core v1.14.9's published
`key_tests.cpp` signature byte-for-byte. The verification corpus includes 476
Wycheproof cases for prehash, DER, curve/scalar and high-S behavior. Payment tests
exercise all six modes, full/compact prevouts, budget checks, external response
rejection without mutation, stale requests, forged final scripts and SINGLE's
historical/new-signing distinction. PSBT tests cover all 34 official BIP174
valid/invalid codec fixtures and eight nontrivial Core sighash vectors.
