# Fixture provenance

`wycheproof.json` contains all 476 cases from
<https://github.com/C2SP/wycheproof/blob/main/testvectors_v1/ecdsa_secp256k1_sha256_test.json>,
retrieved 2026-11-24. Each key, DER signature, tcId, classification, comment and
flag is copied from upstream. The stored digest is SHA256(upstream message),
computed independently using Python hashlib when freezing the fixtures.
This lets tests call the prehash API without depending on its own hashing path.
Upstream's Apache-2.0 license is included as `LICENSE-wycheproof`.

The deterministic signing test in `src/signing.rs` copies the DER expectation
and public test secret from
<https://github.com/dogecoin/dogecoin/blob/v1.14.9/src/test/key_tests.cpp>.
That source is MIT licensed, Copyright (c) 2012-2015 The Bitcoin Core developers;
see <https://github.com/dogecoin/dogecoin/blob/v1.14.9/COPYING>.
The scalar is decoded from the source's public `strSecret1` WIF; the stored
prehash is SHA256d of its literal `Very deterministic message` example.
