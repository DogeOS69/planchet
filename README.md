# planchet

Pure Rust Dogecoin libraries in a shared Cargo workspace. Rust **2024**, MSRV
**1.91**, version **0.1.0**. The project release license is **pending**; every
package inherits `publish = false` for local pre-release use. Third-party
fixtures retain their original licenses, copyright notices and provenance.

The `planchet` crate is the facade. Types live once in their owning leaf crates
and are reexported by the facade; a leaf never depends on the facade. This is an
initial implementation, not a complete Dogecoin consensus validator or wallet.

## Quick start

During development, use the local facade:

```toml
[dependencies]
planchet = { path = "/path/to/planchet/crates/planchet" }
```

Amounts are integer koinu (100,000,000 per DOGE), never floating point:

```rust
use planchet::{Amount, FeeRate, Network, Txid, sha256d};

let payment = Amount::from_doge_str("1.25").unwrap();
assert_eq!(payment.to_koinu(), 125_000_000);
assert_eq!(Amount::from_doge_str("1e-8").unwrap().to_koinu(), 1);
let fee = FeeRate::from_koinu_per_kvb(1_000).fee_for_bytes(250).unwrap();
assert_eq!(fee.to_koinu(), 250);
let txid = Txid::from_wire_bytes(sha256d(b"serialized transaction bytes"));
let raw_digest = txid.to_wire_bytes();
assert_eq!(raw_digest, sha256d(b"serialized transaction bytes"));
assert_eq!(Network::Mainnet.core_name(), "main");
```

`Txid`, `BlockHash` and `MerkleRoot` store wire-order bytes and reverse them once
for `Display`/`FromStr`. `Sighash` and `Hash160` preserve raw digest order in text.
`sha256d` and `hash160` return raw byte arrays. `OutPoint` exposes `txid` and `vout`,
plus `new`, `NULL` and `is_null`.

```rust
use planchet::{Address, AddressKind, Network};

let address = Address::parse(
    "DD4KSSuBJqcjuTcvUg1CgUKeurPUFeEZkE", Network::Mainnet,
).unwrap();
assert_eq!(address.kind(), AddressKind::P2pkh);
assert_eq!(address.to_string(), "DD4KSSuBJqcjuTcvUg1CgUKeurPUFeEZkE");
```

Addresses are Base58Check P2PKH/P2SH. Parsing requires an explicit network and
checks the checksum and version; shared testnet/regtest P2SH encodings cannot
identify a unique chain. Network metadata follows
[Dogecoin Core v1.14.9](https://github.com/dogecoin/dogecoin/blob/v1.14.9/src/chainparams.cpp),
including the distinct testnet (`f1`) and regtest (`ef`) WIF versions. WIF
encoding/private-key storage is not part of primitives.

`Amount::from_doge_str` follows the existing DogeOS amount conversion semantics:
effective fractional scale must be at most eight, **including redundant zeroes**.
Thus `1.000000000` and `0e-9` fail, while `1.000000000e1` succeeds. The exponent
is i32; coefficient and power-of-ten arithmetic is bounded by u128 before a
checked u64 conversion. Zero receives no special overflow/precision bypass.
The legacy text parser accepts `.1`, `1.` and `.`; RPC validates JSON syntax
separately. `Display` emits exactly eight decimal places. Checked arithmetic
returns `Option`; fees round upward per 1,000 bytes, without imposing relay or
dust policy.

## Crates and facade features

| Crate | Responsibility |
| --- | --- |
| `planchet-primitives` | Hash IDs, hashes, outpoints, networks, addresses, amounts, fee rates |
| `planchet-consensus` | Bounded wire views, transactions, scripts, headers/AuxPoW, Merkle and legacy sighash |
| `planchet-rpc-types` | Typed Core RPC values and exact JSON amounts |
| `planchet-transport` | Abstract transport and optional bounded HTTP |
| `planchet-provider` | Core JSON-RPC client and chain reads |
| `planchet-psbt` | Offline PSBT v0 maps and transaction workflows |
| `planchet-signer` | Signing contracts and optional pure Rust local ECDSA |
| `planchet` | Reexports; no duplicate domain types |

| Facade feature | Effect |
| --- | --- |
| default: `alloc` | Primitives and consensus with owned transaction support, no networking |
| no defaults | Allocation-free primitives and borrowed consensus API |
| `std` | `alloc` and the core crates' std configuration |
| `rpc` | `std`, RPC types, provider, abstract transport |
| `http` | `rpc` plus the built-in HTTP transport |
| `psbt` | `alloc` plus PSBT |
| `signer-local` | `alloc` plus the signer crate's `local` feature |
| `pow-scrypt` | Optional consensus scrypt hashing |

For offline work use `default-features = false, features = ["psbt", "signer-local"]`.
For node access use `features = ["rpc", "http"]`. No TLS backend is enabled by
the facade. The built-in HTTP transport is intended for explicitly configured
local/protected connections; it must not silently downgrade HTTPS.
No facade `serde` feature is currently provided.

## Verify a real block

From this repository root, verify the included mainnet genesis raw block offline:

```sh
cargo +1.91.0 run -p planchet-provider --features http --example verify-block -- \
  offline crates/planchet-consensus/tests/fixtures/mainnet-genesis.bin \
  1a91e3dace36e2be3bf030a65679fe821aa1d6ef92e7c9902eb318182c355691
```

Replace the path and expected ID with your own **binary wire-format block**; the
expected ID argument is optional. Offline mode reads only that file and verifies
its block ID and transaction Merkle root. The example requires the `http` build
feature because it contains both CLI modes; offline mode makes no RPC calls.

For a running Dogecoin Core regtest node explicitly configured with
`rpcport=18443`, substitute its configured Basic auth credentials:

```sh
PLANCHET_RPC_USER=your-rpc-user PLANCHET_RPC_PASSWORD=your-rpc-password \
  cargo +1.91.0 run -p planchet-provider --features http --example verify-block -- \
  node http://127.0.0.1:18443 regtest 0
```

Online mode first checks Core's chain name and genesis ID, then verifies the
selected block's raw bytes, ID, Merkle root and stable height anchor. Choose
`mainnet`, `testnet` or `regtest` and the desired height explicitly. This is a
read-only check; it does not validate full AuxPoW or the historical consensus
rules. Successful output includes `merkle=ok` and, online, `anchor=stable`.

## Local verification and dependency policy

Use explicit toolchains; no machine-wide or DogeOS toolchain change is needed:

```sh
cargo +1.91.0 test --workspace --all-features
cargo +1.91.0 test -p planchet --no-default-features
cargo +1.91.0 check -p planchet --no-default-features
cargo +1.91.0 check -p planchet --no-default-features --features psbt,signer-local
cargo +1.91.0 check -p planchet --features rpc,http
python3 scripts/check-dependency-policy.py --check-profiles
python3 scripts/check-dependency-policy.py --no-default-features --target riscv32imac-unknown-none-elf
python3 -m unittest discover -s scripts/tests -v
```

Cargo generates `Cargo.lock`; the policy check uses `--locked` and never edits it.
Dependencies are declared directly in leaf manifests. The root holds shared
package metadata, uses `crates/*`, and does not define workspace dependencies.

The executable Python 3 stdlib policy check follows the target-filtered resolved
graph, including **normal, dev and build** dependencies. It checks actual package
names even when renamed, forbidden aliases/forks, sources (only crates.io and
workspace crate paths), native `links`, native build helpers/crypto bindings and
bundled C/C++/assembly/objects. It lists Rust build scripts and build edges for
source review. Pure Rust build scripts are allowed. System ABI bindings such as
`libc` contain Rust and refer to the platform runtime; they are not bundled
third-party C implementations. Standard Rust target/runtime libraries remain
outside this third-party source screen.

`--check-profiles` also inspects separately selected consumer trees: default and
RPC/HTTP must omit PSBT/signers and elliptic-curve key crates; the WASM
`planchet-signer` `verify,psbt` profile must omit the listed networking crates and
`getrandom`. These are package-identity screens, not whole-program analysis.
The WASM policy profile is configured without the signer's `local` feature.

**Scope:** static screening catches the listed violations; it does not prove
that arbitrary Rust code, build scripts or proc macros cannot invoke native
tools. Check every claimed target/feature graph, review listed build scripts,
then build from a fresh target directory with native tool variables disabled:

```sh
mkdir -p target
CC=/usr/bin/false CXX=/usr/bin/false AR=/usr/bin/false \
  CARGO_TARGET_DIR=target/no-native \
  cargo +1.91.0 build --workspace --all-features --locked --message-format=json \
  > target/native-build.jsonl
cargo +1.91.0 tree --locked --workspace --all-features -e normal,build,dev,features
```

Those environment variables disable conventional native dependency builds;
they are not an isolation boundary against build scripts ignoring them. Rust
may still use the platform linker for its standard runtime. Review Cargo's
`build-script-executed` native link output and linked executable dependencies
(`otool -L` on macOS, `ldd`/`readelf` on Linux) for stronger artifact evidence.
Bare-target core builds establish no_std compilation on that target, not
OpenVM guest compatibility, WASM support, chain validation, or performance.

SHA-256 uses `sha2 0.10` with default features disabled and `force-soft`, without
the optional native assembly package. HASH160 uses `ripemd 0.1`; Base58 uses
`bs58` without default features. Dependencies and actual resolved features, not
crate marketing alone, determine whether a profile satisfies the policy.

Primitive fixture provenance and original MIT terms are recorded in
[VECTORS.md](crates/planchet-primitives/tests/VECTORS.md). Unit-test expected values
are fixed external results or independently justified integer values.

### Recorded local verification

On `aarch64-apple-darwin` with Rust 1.91.0:

- Workspace tests and doctests passed with all features, plus separate facade
  minimal, PSBT-only, signer-only, combined offline, and RPC/HTTP builds/tests.
- The allocation-free facade compiled for `riscv32imac-unknown-none-elf`; the
  signer's `verify,psbt` profile compiled for `wasm32-unknown-unknown`.
- Static policy screening passed for 117 host packages, including dev/build
  dependencies. Default/RPC graphs excluded signing key crates; the WASM policy
  graph excluded the screened networking/entropy dependencies.
- A fresh all-feature, all-target workspace build passed with `CC`, `CXX` and
  `AR` set to `/usr/bin/false`. Cargo build-script messages emitted no native link
  libraries or search paths. `otool -L` inspected 24 executables/proc-macro
  dylibs: only system `libSystem`/`libiconv` and the Rust-built proc-macro dylibs
  appeared. This is evidence for this target and graph, not every future graph.
- The documented offline CLI returned the mainnet genesis ID and `merkle=ok`.
