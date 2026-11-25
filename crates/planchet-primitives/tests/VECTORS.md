# Primitive contract vectors

The tests use fixed expected results, not another path through the implementation.

- Genesis IDs, Merkle roots, header fields and network metadata come from
  [Dogecoin Core v1.14.9 chainparams.cpp](https://github.com/dogecoin/dogecoin/blob/v1.14.9/src/chainparams.cpp).
  The three raw 80-byte headers encode those fields; their expected hashes are
  Core's literal genesis assertions. These catch byte order and network mixups.
- Four address/payload pairs are the first four public address entries in
  [Core v1.14.9 base58_keys_valid.json](https://github.com/dogecoin/dogecoin/blob/v1.14.9/src/test/data/base58_keys_valid.json).
  They catch wrong prefixes, checksums, payloads, and accidental test/regtest inference.
  The regtest zero-HASH160 address was generated independently with Python integer
  base conversion and `hashlib`: the checked payload is
  `6f00000000000000000000000000000000000000008f62b721`.
- Empty/`abc` SHA256d and HASH160 expected hex was generated independently using
  Python 3 `hashlib.sha256` and `hashlib.new('ripemd160', ...)`, outside Rust tests.
- `hashes.rs` checks SHA-256's standard empty/`abc` results and fixed padding
  vectors for `b'a' * n`, with `n = 55, 56, 63, 64, 65, 119, 120, 128`.
  Expected SHA-256, SHA256d, and HASH160 hex came from Python `hashlib` outside
  Rust tests. Split points exercise streamed multipart hashing, and asymmetric
  `a`/`b`/`c` parts protect concatenation order. Offsets 0 through 3 protect
  unaligned input support. These catch dropped/reordered parts, incorrect
  padding, and alignment assumptions across backends.
- Optional Keccak-256 empty/`abc` and `b'a' * n` results came independently from
  PyCryptodome `Crypto.Hash.keccak.new(digest_bits=256, data=...)`. Lengths 135,
  136, 137, 271, 272, and 273 straddle its 136-byte rate and catch SHA3 domain
  separator substitution and boundary padding mistakes. Expected values are
  literals; no alternate implementation runs inside the tests.
- Asymmetric `00..1f` bytes have literal expected text order. Decimal and fee
  expectations use integer place values and hand-calculated upward rounding.
  Decimal compatibility follows the existing DogeOS RPC conversion contract at
  `dogeos-core/crates/dogecoin_rpc_client/src/dogecoin_rpc/amount.rs`: scale is
  checked before multiplying, including zero; the exponent is i32 and the
  coefficient/power arithmetic is bounded by u128. No source code was copied.

Core fixture data retains its original MIT terms. Project release license
selection remains pending:

Copyright (c) 2009-2016 The Bitcoin Core developers
Copyright (c) 2022-2024 The Dogecoin Core developers

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
