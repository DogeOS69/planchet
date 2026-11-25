# Planchet on OpenVM v1.7.0

This separate Cargo workspace runs a fixed verification workload on the actual
OpenVM VM. It does not change the parent workspace, install patches, or modify
production DogeOS guests. The `planchet` dependency disables defaults and always
enables the portable `k256`, `p256`, and `keccak` APIs. Backend features select
implementations; the source, fixtures, assertions, and public output are identical.
Planchet remains `no_std`; this executable uses OpenVM's supported `std` entry.

Use the installed `cargo-openvm v1.7.0 (425913bd)` and compiler
`nightly-2026-03-17` with `rust-src`. The example manifest retains MSRV 1.91.
Every OpenVM dependency uses `tag = "v1.7.0"`, matching the DogeOS source/package
IDs. The committed lockfile freezes it at
`425913bdc743ef44236daf472ec53c2c05b75fa1`. Use `--locked` on all builds.
Dependencies are stable RustCrypto and the tagged public SDK crates, without
local SDK paths, global patches, or C/native crypto libraries.

From this directory:

```sh
export OPENVM_RUST_TOOLCHAIN=nightly-2026-03-17
export RUSTC="$(rustup which --toolchain "$OPENVM_RUST_TOOLCHAIN" rustc)"
cargo openvm --version

# Software, all four accelerated backends, and each backend independently.
python3 scripts/benchmark.py

# Just the paired comparison.
python3 scripts/benchmark.py --variants software accelerated

# Portable host oracle execution, also verifies this example's MSRV.
cargo +1.91.0 run --locked --bin planchet-openvm-verify
```

The script checks the CLI version and lockfile source SHA, explicitly pins both
the SDK guest compiler environment and `RUSTC`, builds each variant, then executes
`cargo openvm run --mode meter` and `--mode segment`. It compares **every public
output byte** across variants and modes against the frozen expected value. Raw
build/run logs, exact commands, compiler metadata, and machine-readable results
are written under `logs/<binary>/`. Builds and proving keys remain under `target/`.
Meter/segment mode may generate an application proving key; neither mode generates
a proof or measures proving time.

Equivalent explicit commands for the paired smoke runs:

```sh
cargo openvm build --locked --no-default-features --bin planchet-openvm-verify \
  --config openvm.toml --output-dir target/runs/planchet-openvm-verify/software
cargo openvm run --locked --bin planchet-openvm-verify \
  --exe target/runs/planchet-openvm-verify/software/planchet-openvm-verify.vmexe \
  --config openvm.toml --mode meter
cargo openvm build --locked --no-default-features --bin planchet-openvm-verify \
  --config openvm.toml --output-dir target/runs/planchet-openvm-verify/accelerated \
  --features accelerated
cargo openvm run --locked --bin planchet-openvm-verify \
  --exe target/runs/planchet-openvm-verify/accelerated/planchet-openvm-verify.vmexe \
  --config openvm.toml --mode meter
```

Replace `--mode meter` with `--mode segment` to obtain segment counts. To enable
one backend independently, replace `accelerated` with `openvm-sha256`,
`openvm-keccak256`, `openvm-k256`, or `openvm-p256`. All four APIs still run.
Always select `--bin` explicitly in SDK commands because this package has two
binaries. Plain `cargo run` retains the smoke binary as `default-run`.

The shared `openvm.toml` follows the
[v1.7 ECC example](https://github.com/openvm-org/openvm/blob/v1.7.0/examples/ecc/openvm.toml)
and includes RV32I/M, I/O, SHA-256, Keccak, and **both** secp256k1 and P-256
curves with their four base/scalar moduli. `cargo openvm build` generates
`openvm_init.rs`; each executable includes it exactly once with `openvm::init!()`.
The configuration and modulus order are identical for every variant. No setup,
curve decoding, signature validation, or failure assertion is removed for metrics.

The smoke workload (`src/main.rs`) uses bounded static inputs, `black_box` at the
input boundary, and consumes every successful hash/verification result in an
asserted 1,028-byte transcript. It publishes SHA-256 of that transcript:
`d0125c20e1feb62adbf3d98b84440beeeb03a1f51cec7aae0057374e98c4a375`.

- `planchet::sha256` and `sha256d`: empty, `abc`, and `0xa3` repeated for
  55, 56, 63, 64, 65, 135, 136, 137, and 1,024 bytes.
- `planchet::keccak256`: empty, `abc`, and 135, 136, 137, and 200 bytes of `0xa3`.
- Ordinary Dogecoin `hash160`, a decoded genesis transaction's `TxRef::txid`,
  `BaseHeader::block_id`, and a three-leaf `merkle_root_checked` including odd-tail
  duplication. Empty and mutated Merkle trees must be rejected.
- Both `planchet::crypto::verify_k256_prehash` and `verify_p256_prehash`: positive
  compressed/uncompressed keys; rejection of a changed prehash, changed signature,
  zero scalars, out-of-range `r`, off-curve key, and truncated key. The exact
  public signature is `(&[u8], &[u8; 32], &[u8; 64]) -> Result<(), VerifyError>`.

These checks protect observable digest, wire-order, and signature-validation
contracts, including backend divergence and accidental rehashing. Expected values
are constants from an independent oracle, never derived from the implementation
inside assertions. See [fixture provenance](fixtures/README.md).

The optional payment binary exercises the public facade's PSBT and signer path
against a frozen, user-supplied Core-accepted regtest transaction:

```sh
# Runs software and accelerated payment, compares complete outputs, meters both.
python3 scripts/benchmark.py --bin payment --variants software accelerated

# Individual build/run; payment is the binary's required feature.
cargo openvm build --locked --no-default-features --bin payment \
  --features payment,accelerated --config openvm.toml \
  --output-dir target/runs/payment/accelerated
cargo openvm run --locked --bin payment \
  --exe target/runs/payment/accelerated/payment.vmexe \
  --config openvm.toml --mode meter

# Host counterpart.
cargo +1.91.0 run --locked --bin payment --features payment
```

`payment` enables only `planchet/psbt` and verification-only `planchet/signer`;
it does not enable local signing or networking. The program decodes the signed
transaction and parent, checks its outpoint, extracts DER/SEC1 and the sighash
byte, computes the legacy sighash, verifies the signature, rejects a wrong
digest, attaches the parent to a PSBT, inserts the final scriptSig, and calls
`finalize_p2pkh` with the original fee budget. It asserts byte-exact signed
serialization and the frozen txid, then publishes the txid's raw 32 wire bytes.
RPC/display txid:
`3cd139ff08015a742456f341bd5a6105954bef85c69ad3e581c429454b8e844a`.
The smoke workload is unaffected when `payment` is disabled. Future PSBT/signer
refactors can rerun this consumer directly in the guest.

Measured on 2026-11-24 using the shipping `scripts/benchmark.py` commands above:

| Binary | Backend feature | `instret` (instructions retired) | Estimated cells (`meter` cost) | Segments |
| --- | --- | ---: | ---: | ---: |
| Smoke | software | 68,553,310 | 5,964,411,703 | 8 |
| Smoke | `accelerated` | 244,184 | 41,980,730 | 1 |
| Smoke | `openvm-sha256` | 68,042,130 | 5,917,943,331 | 8 |
| Smoke | `openvm-keccak256` | 68,400,718 | 5,951,215,385 | 8 |
| Smoke | `openvm-k256` | 47,195,192 | 4,029,523,832 | 6 |
| Smoke | `openvm-p256` | 22,266,074 | 2,036,533,291 | 3 |
| Payment | software (`payment`) | 16,778,548 | 1,527,191,663 | 2 |
| Payment | `payment,accelerated` | 118,529 | 17,385,619 | 1 |

Every mode and backend returned the identical frozen output for its binary.
`instret` and estimated cells are separate SDK measurements, not elapsed cycles
or elapsed time. The smoke pair has 280.74 times fewer retired instructions
and 142.07 times fewer estimated cells with all four backends enabled.

See [captured results and exact commands](RESULTS.md). These are fixed-workload
instruction/estimated-cell comparisons, not proof-time or general throughput
claims. The payment guest rechecks the supplied acceptance fixture; it does not
start Dogecoin Core or claim a new live `testmempoolaccept` run.
