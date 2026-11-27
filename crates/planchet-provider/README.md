# planchet-provider

Rust 2024 / MSRV 1.91. Release license pending. Default features are empty;
`http` enables the optional `planchet-transport` HTTP implementation. An injected
`Transport` works without HTTP dependencies. DTOs are owned by `planchet-rpc-types`.

## Read-only block check

From the workspace root, with an existing node (no wallet required):

```sh
PLANCHET_RPC_USER=rpcuser PLANCHET_RPC_PASSWORD=rpcpassword \
cargo +1.91.0 run -p planchet-provider --features http --example verify-block -- \
  node http://127.0.0.1:18443 regtest 106
```

Both authentication environment variables must be supplied together, or omitted.
The endpoint must use explicit HTTP on a trusted/local connection. This build
rejects HTTPS, and never downgrades or follows a redirect. Configure an application
transport to use an independently vetted TLS implementation if needed.

The example checks `getblockchaininfo.chain` and `getblockhash(0)` against the
selected primitives `Network`, reads the requested height's anchor, retrieves
raw bytes, calls `BlockRef::decode_exact(&bytes, DecodeLimits::default())`, compares
`.header().block_id()` with the anchor, calls `.check_tx_merkle_root()`, and reads
`getblockhash(height)` again. A changed anchor fails the operation. Output is a
block ID, byte count, and successful Merkle/anchor checks. The example sends only
read RPCs. No signing, wallet import, rescan, broadcast, or block generation occurs.

Offline binary wire data uses the same supported `check_raw_block` library API:

```sh
cargo +1.91.0 run -p planchet-provider --features http --example verify-block -- \
  offline /absolute/path/block.bin [expected-block-hash]
```

Omit the optional bracketed argument if no external block ID is available. The
file reader rejects more than 64 MiB. The offline library API itself needs no
HTTP feature. These checks establish structural decoding, ID, and transaction
Merkle integrity. They do not verify scripts, PoW/AuxPoW commitments, difficulty,
best-chain selection, or finality.

## Typed calls and observations

`Client<T>` handles Core JSON-RPC 1.0 envelopes, matching monotonically allocated
IDs shared by clones, required result/error fields, structured Core errors even
on HTTP 500/503, and method-specific deserialization. Null is accepted only when
the requested result type allows it. It does not retry. Raw numeric tokens are
parsed directly, without an intermediate floating-point JSON value.

`Provider<T>` exposes:

- Chain reads: blockchain/network info, block count, best hash, height-to-hash,
  chain tips, raw block, hashes/full verbose block, raw/base/verbose headers.
- Transactions/mempool: raw/verbose transaction, decoderawtransaction,
  raw mempool txids, mempool info/entry, nullable gettxout.
- `get_transaction_by_hash(txid).await`: one `getrawtransaction(txid, true)` call,
  returning `types::TransactionResponse` after checking the requested txid.
  Its public `transaction: BlockTransaction` includes full ordered inputs/outputs,
  Core's `Wtxid`, size fields and optional hex of Core-supplied serialized bytes;
  no local reconstruction is performed. `blockhash`, signed `confirmations`,
  `time` and `blocktime` are optional observations, not guarantees of active-chain
  inclusion or finality. All Core errors are retained, including `-5`: unavailable
  data or missing txindex is not proof of absence. There are no retries or extra
  calls. The name follows [Alloy's lookup API](https://docs.rs/alloy-provider/2.6.1/alloy_provider/trait.Provider.html#method.get_transaction_by_hash),
  adapted to Core error semantics rather than an optional absence result.
  Existing `transaction_info`, `decode_transaction`, `raw_transaction` and their
  lightweight callers keep their contracts.
- `utxo_status`: Unspent / Spent / Unknown, selected confirmed-only or mempool
  view, and a best-tip bracket. Null requires a known parent and valid output
  index before any spend inference. Confirmed parents require positive active
  confirmations and a matching canonical hash at their reported block height.
  Missing txindex, unseen/pruned parents, stale parents, invalid indices and
  mempool eviction remain Unknown. A tip change fails the observation.
- `broadcast`: hashes the exact submitted bytes locally, sends once, checks the
  returned txid, and returns `SubmissionUnknown { txid, cause }` on an ambiguous
  transport/response failure. A Core RPC rejection preserves the node's code.
  Reconciliation and any later resubmission belong to the caller.
- Basic watch-wallet operations are isolated in `wallet.rs`, including complete
  capped `listunspent` and ordered per-request `importmulti` results. They mutate
  only when explicitly called. Wallet tests and DTOs are maintained separately.

The block reader follows Alloy's single-entry request builder and transaction
representation patterns: [Provider::get_block](https://docs.rs/alloy-provider/2.6.1/alloy_provider/trait.Provider.html#method.get_block),
[Provider::get_block_by_hash](https://docs.rs/alloy-provider/2.6.1/alloy_provider/trait.Provider.html#method.get_block_by_hash)
and [BlockTransactions](https://docs.rs/alloy-network-primitives/2.6.1/alloy_network_primitives/enum.BlockTransactions.html).
It uses Dogecoin Core RPC and UTXO DTOs without an Alloy dependency:

```rust
use planchet_provider::BlockId;

let latest = provider.get_block(BlockId::Latest).await?;
let at_height = provider.get_block_by_height(106).full().await?;
let block = provider.get_block_by_hash(hash).await?; // getblock(hash, 1)
let full = provider.get_block_by_hash(hash).full().await?; // getblock(hash, 2)
let reset = provider.get_block_by_hash(hash).full().hashes().await?;
```

`GetBlock` is a lazy, Send `IntoFuture`; building, changing modes, or dropping an
unpolled request sends nothing. Hash selectors send one RPC through the same
Client. `BlockId::Height(height)` (also `get_block_by_height(height)`) resolves
with `getblockhash(height)`; `BlockId::Latest` resolves with `getbestblockhash()`.
Each then fetches the resolved hash with `getblock`, for two RPCs total. These
reads observe that resolved hash even if the chain reorgs afterwards, so the
returned block may be stale. There is no extra tip read or automatic retry;
lookup and fetch errors propagate unchanged. Callers needing a stronger
bracketed raw block check can use `check_block_at_height(height)`.
Height selectors also verify that the returned header height matches the request.
Both modes return `types::Block { header, size, transactions }`. The request
selects `BlockTransactions::Hashes` or `Full`, including for empty arrays;
responses in the wrong mode fail decoding. Both modes check the returned block
hash. `block_info` retains its existing signature and `header`, `size`, `tx`
fields, sharing the default builder's execution and decoding path.

Verbose reads never construct a serialized transaction/block from incomplete
verbose JSON. `raw_block_header` exact-decodes a complete native/AuxPoW
`WireHeader`; an 80-byte AuxPoW base is rejected. `base_block_header` supports
that narrower observation. For nodes exposing only the base through
`getblockheader(false)`, callers can explicitly fetch `raw_block` for the complete
header. No fallback RPC is automatically replayed. Legacy boolean `getblock`
verbosity is explicit `with_block_verbosity(BlockVerbosity::LegacyBoolean)`.
Hashes then use `true`; full transactions fail locally with
`Error::UnsupportedBlockVerbosity` before any hash lookup and send no RPC.
No mode automatically retries.

Best-tip bracketing is an observation, not an atomic node snapshot. It cannot
exclude a tip changing away and back, or a mempool change within a stable tip.
Applications retain their own reconciliation/finality and database policies.

## Limits and errors

Default response limit is 64 MiB. `Client::call_with_response_limit(method,
params, cap)` permits an explicit per-method budget; `HttpConfig` still imposes
its separate hard ceiling. Raise that ceiling explicitly to use a wallet's
1 GiB migration profile. Streaming bodies and declared content lengths are
checked, with an additional check in Client for injected transports. Complete
snapshots fail on any cap; no prefix is returned as complete.

The HTTP transport has a concurrency budget, connect timeout, and a total
request deadline covering queueing and body reading. Dropping a future cancels
observation, not a node operation already received. Error variants retain RPC
method/code/message/data and HTTP status, distinguish malformed responses,
HTTP failures, transport timeout/size/I/O, network mismatch, hash mismatch,
anchor/tip changes, and ambiguous submissions. No request bodies or credentials
appear in transport/request/client Debug output; raw reqwest URL errors are
intentionally not exposed.

## Executed verification

```sh
cargo +1.91.0 test -p planchet-rpc-types -p planchet-transport -p planchet-provider --all-features
cargo +1.91.0 test -p planchet-rpc-types -p planchet-transport -p planchet-provider --no-default-features
cargo +1.91.0 clippy -p planchet-rpc-types -p planchet-transport -p planchet-provider --all-features --all-targets --no-deps -- -D warnings
```

The general suite includes real localhost HTTP tests, offline block checks,
exact-number DTO tests, and request-builder contracts in `tests/http.rs`. The latter
cover default/full/reset modes, laziness and Send, empty variants, legacy behavior,
wrong modes/hashes, and the complete Core 1.14.9 recording with coinbase/payment
ordering and exact amounts. Separate tests in that file cover Core errors across
HTTP statuses (`structured_core_errors_survive_non_success_statuses`) and rejection
without a boolean fallback/replay on the raw-block path
(`legacy_boolean_is_explicit_and_never_replayed_on_error`). HTTP checks include raw/verbose data,
complete versus base-only AuxPoW headers, null, non-2xx Core errors, malformed or
missing envelopes, mismatched/string/null/duplicate IDs, exact body-size boundary,
chunked/declared oversize bodies, per-call versus transport limits, Basic auth,
redacted Debug/errors, unsupported schemes/redirects, network/genesis identity,
anchor/tip drift, confirmed/mempool/unknown UTXO evidence, raw transaction IDs,
and broadcast timeout/rejection/returned-ID mismatch without replay. Accepted
fake-server sockets are explicitly blocking with finite I/O deadlines on macOS.

Expected genesis IDs/txids and AuxPoW bytes come from independent Core recordings;
amount expectations use fixed decimal-place integer values. Offline cases reject
trailing/truncated bytes, wrong IDs, and corrupt Merkle roots. Wallet coverage is
in `tests/wallet.rs`; its live isolated-regtest test is opt-in and ignored by the
ordinary suite. This is behavioral coverage, not a measured line/branch percentage.

CI runs `python3 scripts/test-provider-wallet-regtest.py` from the workspace root
in the existing Linux job, using a disposable official Core 1.14.9 node at genesis
(no mining). It requires exactly one passing live test and cleans up its node.
Against your own isolated regtest node, set
`PLANCHET_WALLET_RPC_URL`, `PLANCHET_WALLET_RPC_USER`, and
`PLANCHET_WALLET_RPC_PASSWORD`, then run
`cargo +1.91.0 test --locked -p planchet-provider --features http --test wallet isolated_regtest_watch_import_read_and_rescan -- --exact --ignored`.
This imports watch addresses and rescans that wallet.

The parent also reported successful live read-only checks on Core 1.14.9 regtest
heights 0, 105, 106 (AuxPoW), and 107 plus invalid/unknown UTXO observations.
