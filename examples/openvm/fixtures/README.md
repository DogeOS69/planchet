# Frozen fixture provenance

`mainnet-genesis.bin` is the 224-byte fixture copied without modification from
`crates/planchet-consensus/tests/fixtures/mainnet-genesis.bin` in this repository.
The first 80 bytes are the header, byte 80 is the one-transaction count, and the
remaining 143 bytes are the complete legacy coinbase. Its known RPC IDs are:

- Block: `1a91e3dace36e2be3bf030a65679fe821aa1d6ef92e7c9902eb318182c355691`.
- Transaction/Merkle root:
  `5b2a3f53f605d62c53e62932dac6925e3d74afa5a4b459745c36d42d0ed26a69`.

`payment-parent.bin` (226 bytes) and `payment-signed.bin` (192 bytes) are the
user-supplied **Dogecoin Core 1.14.9 regtest** qualification fixtures. Their bytes
match the qualification's frozen funding transaction and independently signed,
Core-accepted payment. The payment spends parent output 0 (200,000,000 koinu),
pays 199,000,000 koinu, and has a **1,000,000 koinu fee** (0.01 DOGE).
`src/bin/payment.rs` adapts the supplied PSBT/signature verification and
finalization consumer to the public facade, uses the same fee budget, and adds
explicit frozen txid and script push assertions. No private keys are included.

- Parent RPC txid:
  `e6c776786ea59351c0c0dd43c3c0e1fb3accc656c4909a85e2c7df323df289d5`.
- Signed RPC txid:
  `3cd139ff08015a742456f341bd5a6105954bef85c69ad3e581c429454b8e844a`.
- Signed raw/wire txid (guest public output):
  `4a848e4b4529c481e5d39ac685ef4b9505615abd41f35624745a0108ff39d13c`.

| File | SHA-256 of the file bytes |
| --- | --- |
| `payment-parent.bin` | `25d375029b70c6139e7ba83d97ffd1176a5c46c4088533d9e355e24884554dcc` |
| `payment-signed.bin` | `f0b9d0e1011d4b273410bd83d89b7fd35df760f28955bc55bff1917bfb7bf7de` |

`src/fixtures.rs` freezes primitive expected values. Regenerate/audit from this
directory with `python3 scripts/generate-fixtures.py`, then
`cargo +1.91.0 fmt`. The generator is a development-only Python oracle:

- SHA-256/SHA256d and HASH160 use standard `hashlib`, independently of Planchet.
- Keccak uses a standalone Python integer implementation of Keccak-f[1600],
  checked against the published empty and `abc` Keccak-256 vectors. The inputs
  exercise the 136-byte rate/padding boundary and differ from SHA3 padding.
- ECDSA uses standard secp256k1/P-256 generator coordinates, public test private
  scalar `d=1`, public nonce `k=1`, and `z=SHA256("abc")`. By the defining ECDSA
  equation, `r=G.x mod n` and `s=(z+r) mod n`; choose `min(s,n-s)` for low S.
  This independent construction supplies the same compact big-endian signature
  to both backends. The fixtures are test data, not a signing recipe for real
  funds. A changed prehash or `s` must fail; zero/out-of-range scalars, the
  off-curve point `(0,0)`, and a truncated SEC1 key must fail.
- Three Merkle leaves are SHA256d of ASCII `leaf0`, `leaf1`, and `leaf2`.
  The oracle explicitly hashes `H(H(L0||L1)||H(L2||L2))` with `H=SHA256d`.
- The final transcript oracle appends the primitive hash bytes in workload
  order, then sixteen successful assertion verdict bytes. Every guest variant
  must match its frozen SHA-256 value.

The Python generator and host fixture audit do not run inside the guest and add
no native-crypto runtime dependency to Planchet or its executable.
