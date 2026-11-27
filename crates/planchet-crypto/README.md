# planchet-crypto

`no_std`, portable Rust SHA-256 and prehashed ECDSA; MSRV 1.91. No allocator
or optional curve dependencies are needed by default. SHA-256 uses `force-soft`.

| Feature | API |
| --- | --- |
| `crypto-backend` | One-time application provider registration; enables no optional algorithms |
| `k256` | secp256k1 public-key validation and prehashed verification |
| `p256` | P-256 public-key validation and prehashed verification |
| `keccak` | Keccak-256 provider method (not SHA3-256) |

`CryptoProvider: Sync` is object-safe. Its `sha256` and `sha256_parts` methods
are always available. `sha256_parts(&[&[u8]]) -> [u8; 32]` computes **one** digest
of the concatenation, streaming without allocation in software. `keccak256`,
`validate_k256_public_key`, `verify_k256_prehash`, `validate_p256_public_key`, and
`verify_p256_prehash` follow their algorithm features. Every method has a portable
software default, independent of the global provider, so partial overrides never
recurse. An adapter's algorithm features must enable matching public features;
algorithms unified by other consumers safely inherit software defaults.

`SoftwareCrypto` implements these defaults. `crypto_provider() -> &'static dyn
CryptoProvider` returns the installed provider or software. With `crypto-backend`,
`install_default_provider(&'static dyn CryptoProvider) -> Result<(), &'static dyn
CryptoProvider>` installs once and returns the attempted provider on failure.
Reading or using the fallback does not reserve the slot. Exactly one concurrent
installer succeeds, even if all attempt to install the same pointer. Install
before cryptographic work begins; an operation that already obtained software
may complete after installation.

Registration uses `spin::Once` on targets with 8-bit atomics. Without atomics it
uses `critical-section` 1.2; the final application must supply its runtime's
implementation. This library selects no interrupt, single-core, or restore-state
assumptions. No synchronization dependency is required without `crypto-backend`.

```rust,ignore
pub fn verify_k256_prehash(
    sec1_key: &[u8],
    prehash: &[u8; 32],
    compact_signature: &[u8; 64],
) -> Result<(), VerifyError>;
// verify_p256_prehash has the identical signature.
```

Keys must be compressed or uncompressed SEC1 encodings, with canonical coordinates
and a non-identity point on the curve. Signatures are big-endian `r || s`; both
scalars must be nonzero and below the curve order. Both low and high S are
mathematically accepted. Callers retain DER decoding and signing/consensus policy.
Prehashes are never hashed again. `VerifyError` distinguishes `InvalidPublicKey`
from `InvalidSignature`, with invalid keys taking precedence in software.

`K256VerifyingKey` and `P256VerifyingKey` retain provider-validated canonical
compressed SEC1 bytes. Equality identifies the same curve point across compressed
and uncompressed input. Their `from_sec1_bytes` and `verify_prehash` methods use
the provider, including verification of a key created before installation.
Cryptographic accelerators belong to application adapters implementing this trait.
