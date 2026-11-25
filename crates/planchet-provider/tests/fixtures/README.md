The regtest genesis block is the public Dogecoin genesis transaction and header,
serialized according to Dogecoin Core v1.14.9 `src/chainparams.cpp`:
https://github.com/dogecoin/dogecoin/blob/v1.14.9/src/chainparams.cpp
Expected genesis ID: 3d2160a3b5dc4a9d62e7e66a295f70313ac808440ef7400d6c0772171ce973a5
Expected coinbase txid/Merkle root: 5b2a3f53f605d62c53e62932dac6925e3d74afa5a4b459745c36d42d0ed26a69

The regtest height-106 AuxPoW block is the same fixed sample used by this
workspace's planchet-consensus tests (regtest-106-auxpow.bin). It is test data,
not a dependency on the old nintondo implementation. Expected block ID:
76c8c746788452725dec232c8897bf56f0dab9e50c5cfe97ef105134b4a5a666;
complete header is 297 bytes. These expectations were frozen separately from
provider/transport code. Generated during qualification with **Dogecoin Core
1.14.9** on 2026-11-24: regtest `getblockhash 106` selects the block;
`getblock <block-hash> 0` supplies its raw hex-decoded bytes, and
`getblockheader <block-hash> false` supplies the complete header. The consensus
fixture provenance records these RPC identities and the independent Core/Python
hash expectations.

No Core implementation code is copied here. Dogecoin Core source retains its MIT
license; the project release license for newly written tests and fake-server
code remains pending.
