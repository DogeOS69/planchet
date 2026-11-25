# Wire fixture provenance

These files contain public test-chain wire data, no private keys or credentials.
The project release license is pending. No DogeOS or Dogecoin Core implementation
source was copied into these tests. The independently written parser uses Core
as a format reference; Core's source remains under its MIT license.

## Core 1.14.9 recordings

Generated during qualification with **Dogecoin Core 1.14.9** on 2026-11-24.
Regtest block IDs are selected with `getblockhash <height>`; raw block bytes are
the hex-decoded result of `getblock <block-hash> 0`, and full header bytes are
obtained with `getblockheader <block-hash> false`. These RPC identities and the
fixed expectations in `blocks.tsv` define the provenance independently of any
local qualification directory.

| Retained file | Chain / height | Bytes | Description |
| --- | --- | ---: | --- |
| `regtest-genesis.bin` | regtest / 0 | 224 | Regtest genesis |
| `regtest-1.bin` | regtest / 1 | 226 | Node-mined native block |
| `regtest-105.bin` | regtest / 105 | 418 | Node-mined native block, coinbase and real transfer |
| `regtest-106-auxpow.bin` | regtest / 106 | 434 | Core-accepted AuxPoW block, 297-byte full header |
| `mainnet-genesis.bin` | mainnet / 0 | 224 | Core mainnet genesis serialization |
| `testnet-genesis.bin` | testnet / 0 | 224 | Core testnet genesis serialization |

Block 106's independently recorded Core block ID is
`76c8c746788452725dec232c8897bf56f0dab9e50c5cfe97ef105134b4a5a666`.
Its 95-byte parent coinbase has **zero outputs**; this is the minimal parent
construction in upstream
[`scrypt_auxpow.py`](https://github.com/dogecoin/dogecoin/blob/v1.14.9/qa/rpc-tests/test_framework/scrypt_auxpow.py).
The parent txid is frozen in `parent-txid.txt`. The AuxPoW parent coinbase does
not appear in the child's ordered transaction list. This fixture demonstrates
acceptance by that node; our structural decoder does not validate AuxPoW PoW.

Three genesis IDs and their common transaction Merkle root agree with the
assertions in
[`chainparams.cpp`](https://github.com/dogecoin/dogecoin/blob/v1.14.9/src/chainparams.cpp).
These constants are independent of planchet.

## Existing DogeOS native fixtures

`dogeos-regtest-{429..434}.bin` are the six raw block strings extracted from
`crates/circuits/common/dogecoin/src/fixtures.rs`, `pub mod block`, in the supplied
DogeOS checkout at commit `7faa5e687ee9205ed3eab520e4b31ffa1538811d`.
Only the public wire bytes were retained. Their origin is the existing regtest
corpus, not a new claim of mainnet acceptance. Block 429's signed deposit txid
also agrees with that source's independently recorded `TX_ID`:
`7abbaa262bcad1b2701f9baf2e7e072aee4ca6a1b55a51fbf290736f0b3b22a0`.
Block IDs for 429..433 are cross-checked by the following block's previous hash.

## Structural parent witness fixture

`structural-witness-header.bin` is **synthetic structural data**, derived from
the accepted block 106 header. It retains the native fields and parent header,
inserts marker/flag `00 01` into the parent, and puts a two-item witness after
its outputs: bytes `00..1f` and `de ad`. The coinbase branch is two hashes
`00..1f` and `20..3f`, with index 3. The chain branch is one hash `40..5f`, with
index 1. It is 432 bytes. The parent txid must remain the same as in 106 because
witness is excluded. These altered branches are not claimed to constitute a
valid mining commitment.

## Independent expected values

`blocks.tsv` freezes the block ID, header Merkle root, full header byte length,
ordered txids, and each transaction's output values for every full-block file.
An independent Python `struct`/`int.from_bytes` cursor located transaction
boundaries and read values; Python `hashlib.sha256` computed hashes, without
loading or invoking planchet or the old Rust decoder. Hash columns use RPC
order (the reverse of raw SHA256d bytes). The tests consume these fixed values,
not an implementation of the decoder in assertions.

The synthetic signed transaction's txid and fixed Merkle roots in `wire.rs`
were similarly computed with Python `hashlib`. Merkle leaves are `[n;32]`,
`n=1..count`. Independent reference pseudocode for generating expected roots:

```python
from hashlib import sha256
def h(raw): return sha256(sha256(raw).digest()).digest()
nodes = [bytes([n]) * 32 for n in range(1, count + 1)]
while len(nodes) > 1:
    if len(nodes) % 2: nodes.append(nodes[-1])
    nodes = [h(nodes[i] + nodes[i+1]) for i in range(0, len(nodes), 2)]
print(nodes[0].hex())  # wire/digest order, not RPC order
```

This independent, allocating level algorithm is only a provenance description;
production uses a bounded streaming stack. Malformed-count, truncation,
nonminimal CompactSize, witness flag, resource-limit, script-range, and mutation
tests assert explicit contracts and fixed errors without copying production
logic into mocks.
