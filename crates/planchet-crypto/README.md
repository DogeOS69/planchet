# planchet-crypto

`no_std`, pure Rust curve verification; MSRV 1.91. No default curve dependencies.

```rust,ignore
pub fn verify_k256_prehash(
    sec1_key: &[u8],
    prehash: &[u8; 32],
    compact_signature: &[u8; 64],
) -> Result<(), VerifyError>;
// verify_p256_prehash has the identical signature.
```

Select `k256` and/or `p256`. Keys must be compressed or uncompressed SEC1
encodings, with canonical coordinates and a non-identity point on the curve.
Signatures are big-endian `r || s`; both scalars must be nonzero and below the
curve order. Both low and high S are mathematically accepted. Callers retain
DER decoding and signing/consensus policy. Prehashes are never hashed again.
`VerifyError` distinguishes `InvalidPublicKey` from `InvalidSignature`.

`K256VerifyingKey` and `P256VerifyingKey` cache a validated, backend-selected
key for callers that parse and verify separately. Their `from_sec1_bytes` and
`verify_prehash` methods have the same validation and signature semantics.

`openvm-k256` / `openvm-p256` include the corresponding curve and select the
upstream OpenVM fork only on `target_os = "zkvm"` and `target_arch = "riscv32"`. Hosts and WASM continue to
use RustCrypto. These are separate dependencies, never global Cargo patches;
private-key signing must continue to use RustCrypto. The OpenVM source is
`tag = "v1.7.0"`, frozen by the lockfile to
`425913bdc743ef44236daf472ec53c2c05b75fa1`, matching DogeOS package IDs.

The guest executable owns initialization: call `openvm::init!()` once, using
the generated initialization file for its `openvm.toml`. This library does not
emit initialization symbols. Both curves may be selected together; configure
both `Secp256k1Point` and `P256Point`, and all four distinct base/scalar moduli
in one guest configuration. Do not emit independent per-curve initialization
macros. The harness can import these point types from the same tagged upstream
packages used here.
