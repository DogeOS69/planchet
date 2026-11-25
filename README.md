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
`sha256`, `sha256d` and `hash160` return raw byte arrays. `OutPoint` exposes
`txid` and `vout`, plus `new`, `NULL` and `is_null`.

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
| `planchet-crypto` | Optional secp256k1/P-256 prehash verification and OpenVM backends |
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
| `signer` | `alloc` plus signer verification, without local private-key signing |
| `signer-local` | `signer` plus the signer crate's `local` feature |
| `pow-scrypt` | Optional consensus scrypt hashing |
| `keccak` | Portable `planchet::keccak256` (Keccak-256, not SHA3-256) |
| `k256` / `p256` | `planchet::crypto::verify_k256_prehash` / `verify_p256_prehash` |
| `openvm-sha256` | OpenVM SHA-256 on RISC-V zkVM, including SHA256d and HASH160's SHA step |
| `openvm-keccak256` | `keccak` plus OpenVM Keccak-256 on RISC-V zkVM |
| `openvm-k256` | `k256` plus OpenVM verification; forwards to already-enabled PSBT/signer crates |
| `openvm-p256` | `p256` plus OpenVM verification; does not enable PSBT/signer |
| `openvm` | Convenience opt-in for all four OpenVM backends |

For offline work use `default-features = false, features = ["psbt", "signer-local"]`.
For node access use `features = ["rpc", "http"]`. No TLS backend is enabled by
the facade. The built-in HTTP transport is intended for explicitly configured
local/protected connections; it must not silently downgrade HTTPS.
No facade `serde` feature is currently provided.

## Hashes and curve verification

Portable host or WASM consumers opt into just the needed algorithms:

```toml
planchet = { path = "/path/to/planchet/crates/planchet", default-features = false, features = ["keccak", "k256", "p256"] }
```

```rust
use planchet::{sha256, keccak256};
use planchet::crypto::{verify_k256_prehash, verify_p256_prehash, VerifyError};

let digest: [u8; 32] = sha256(b"message");
let ethereum_digest: [u8; 32] = keccak256(b"message");
// Pass the scheme's precomputed digest, SEC1 public key and compact r || s.
let bad_key = verify_k256_prehash(&[], &digest, &[0; 64]);
assert_eq!(bad_key, Err(VerifyError::InvalidPublicKey));
assert_eq!(verify_p256_prehash(&[], &ethereum_digest, &[0; 64]), bad_key);
```

The curve API consumes an explicit 32-byte prehash and a 64-byte big-endian
compact `r || s` signature; it does not hash again or parse DER. It checks
SEC1 encoding, point validity, nonidentity, scalar ranges and the ECDSA equation.
Both low and high S are mathematically valid at this layer. PSBT and signer
callers retain their existing strict DER, historical-signature and low-S policy.
`K256VerifyingKey` / `P256VerifyingKey` cache a validated backend-selected key.
Local private-key signing stays on RustCrypto, including with OpenVM enabled.

### OpenVM opt-ins and limits

An OpenVM consumer can request `features = ["openvm"]`, or select individual
`openvm-*` features. Add `psbt` and/or `signer` for checked offline workflows;
`signer` verifies without enabling `signer-local`. Weak optional dependency
forwarding means an accelerator alone does not pull in PSBT or the signer.
Native and WASM builds with those same flags use portable RustCrypto backends;
they do not execute VM instructions. Defaults and RPC/HTTP do not pull in curves.

Guest selection uses the SDK's **`riscv32im-risc0-zkvm-elf`** target, whose
`target_os` is `zkvm`. A generic bare RISC-V build does not select OpenVM.
Dependencies use `tag = "v1.7.0"` with the lock frozen to
`425913bdc743ef44236daf472ec53c2c05b75fa1`. Keep the same URL, tag selector
and SHA as DogeOS; spelling the same commit as a `rev` dependency creates a
different Cargo source identity. Build with `--locked`; no global crypto patches
are needed.

The guest executable owns `openvm::init!()` and its generated initialization
file. Configure the SHA-256, Keccak, modular-arithmetic and ECC extensions it
uses. Enabling both curves requires one configuration containing both curve
points and all four distinct base/scalar moduli; avoid separate initialization
macros that define conflicting symbols. The curve bridge registration must match
`Secp256k1Point` and `P256Point`, with each curve's coordinate and scalar modulus
registered in the same order as `openvm.toml`; P-256 cannot reuse secp256k1's
registration or omit its scalar field. The executable includes the generated
`moduli_init!` / `sw_init!` registration once via `openvm::init!()`, and the SDK
performs curve setup without skipping key or signature validation. See the
[guest harness README](examples/openvm/README.md) for its VM configuration and
build/run instructions.

An analogous real API is
[Alloy primitives 1.5.7's Keccak backend selection](https://github.com/alloy-rs/core/blob/v1.5.7/crates/primitives/src/utils/mod.rs):
its `keccak256` can use a VM's `native-keccak` hook; enabling `sha3-keccak` or
`tiny-keccak` overrides that hook. Its streaming `Keccak256` uses software.
Planchet similarly makes backend choice explicit, but its OpenVM flags select
safe SDK wrappers on the guest and keep portable host fallbacks automatically.

Acceleration covers calls that reach these wrappers, not every cryptographic
operation in the dependency graph. SHA256d invokes accelerated SHA twice;
HASH160 retains software RIPEMD-160. Consensus multipart SHA256d streams on the
host but joins multiple nonempty slices into one guest allocation for the
contiguous SDK API; wrappers may also allocate for alignment. Curve arithmetic
and verification can use OpenVM while DER parsing, policy checks and local
signing retain their Rust implementations. Scrypt is a separate optional PoW
feature and is not accelerated. Feature flags and compilation alone establish
neither proof correctness nor a performance gain; measure the actual guest.

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
python3 scripts/check-dependency-policy.py --openvm
python3 scripts/check-dependency-policy.py --no-default-features --target riscv32imac-unknown-none-elf
python3 -m unittest discover -s scripts/tests -v
```

Cargo generates `Cargo.lock`; the policy check uses `--locked` and never edits it.
Dependencies are declared directly in leaf manifests. The root holds shared
package metadata, uses `crates/*`, and does not define workspace dependencies.

The executable Python 3 stdlib policy check follows the target-filtered resolved
graph, including **normal, dev and build** dependencies. It checks actual package
names even when renamed, forbidden aliases/forks, sources (crates.io, workspace
crate paths, and an enumerated set of exactly pinned OpenVM guest packages),
native `links`, native build helpers/crypto bindings and bundled C/C++/CUDA,
assembly and objects. The only assembly exception is the pinned `openvm` runtime's
`src/memcpy.s` and `src/memset.s`, checked by full source identity, version, path
and SHA-256 file digest. These are RISC-V VM memory routines generated upstream
from musl C; guest builds do not compile that C. No C or native crypto exception
is granted, and other SDK packages, revisions and assembly remain screened.
It lists Rust build scripts and build edges for source review. Pure Rust build scripts are allowed. System ABI bindings such as
`libc` contain Rust and refer to the platform runtime; they are not bundled
third-party C implementations. Standard Rust target/runtime libraries remain
outside this third-party source screen.

`--check-profiles` also inspects separately selected consumer trees: default and
RPC/HTTP must omit PSBT/signers and elliptic-curve key crates; the WASM
`planchet-signer` `verify,psbt` profile must omit the listed networking crates and
`getrandom`. These are package-identity screens, not whole-program analysis.
The WASM policy profile is configured without the signer's `local` feature. The
host `openvm` opt-in profile must omit PSBT, the signer and entropy packages.

`--openvm` screens the facade's actual `openvm,psbt,signer` graph, without defaults,
on `riscv32im-risc0-zkvm-elf`. `--check-profiles` includes that check as well as
the existing host/WASM separation checks. Cargo's selected normal/dev/build tree
includes host proc macros and build scripts, all of whose sources are screened.
A separate `normal,no-proc-macro` runtime tree must exclude entropy: upstream
`openvm-algebra-moduli-macros` uses `num-prime` and host `getrandom`, but guest
runtime entropy is rejected. The profile also requires all four pinned
accelerators and keeps local signing disabled. This does not establish an
entropy-free build host. The audit rejects a moved OpenVM tag in `Cargo.lock`
even when running only a host profile.

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
Bare-target core builds establish no_std compilation on that target. To compile
the actual OpenVM library graph with MSRV Rust and its matching `rust-src`:

```sh
rustup component add rust-src --toolchain 1.91.0
CC=/usr/bin/false CXX=/usr/bin/false AR=/usr/bin/false \
  RUSTC_BOOTSTRAP=1 CARGO_TARGET_DIR=target/openvm-no-native \
  cargo +1.91.0 build -p planchet --locked --no-default-features \
  --features openvm,psbt,signer --target riscv32im-risc0-zkvm-elf \
  -Zbuild-std=core,alloc -Zbuild-std-features=compiler-builtins-mem
```

`build-std` needs nightly Cargo features; this opt-in uses Rust 1.91.0 for an
MSRV compilation check. The executable harness uses the SDK guest toolchain and
initialization workflow. A library build does not execute a guest, generate or
verify a proof, establish complete chain validation, or measure performance.

Portable SHA-256 uses `sha2 0.10` with default features disabled and `force-soft`,
without the optional native assembly package. HASH160 uses `ripemd 0.1`; Base58 uses
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

After adding the optional OpenVM backends, the host policy screened 126 packages
and the actual zkVM verification profile screened 91 (including host build tools).
Default/RPC separation, WASM separation, exact OpenVM source/assembly checks and
13 policy regression tests passed. The facade also passed host all-feature tests,
a WASM curve/PSBT/verification build, and the Rust 1.91.0 actual-target library build
with conventional native build tools disabled. Separate real guest runs cover
software, combined acceleration, each backend individually, and the checked
PSBT/payment path, comparing complete public outputs in meter and segment modes;
see the [guest harness README](examples/openvm/README.md). These executions do not
generate proofs or measure proving time.
