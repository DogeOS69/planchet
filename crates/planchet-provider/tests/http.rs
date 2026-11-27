#![cfg(feature = "http")]
mod support;
use planchet_primitives::{Network, OutPoint};
use planchet_provider::{
    BlockId, Client, ClientConfig, Error, Provider, UtxoStatus, UtxoUnknown,
    transport::{BasicAuth, Error as TransportError, HttpConfig, HttpTransport},
    types::{BlockTransactions, BlockVerbosity, SpendView, TransactionInputKind},
};
use serde_json::json;
use std::{
    future::IntoFuture,
    io::Write,
    net::TcpListener,
    thread,
    time::{Duration, Instant},
};
use support::*;
fn transport(server: &Server) -> HttpTransport {
    HttpTransport::new(
        &server.url,
        Some(BasicAuth::new("user", "pass")),
        HttpConfig::default(),
    )
    .unwrap()
}
fn quote(s: &str) -> String {
    serde_json::to_string(s).unwrap()
}
fn tip() -> Step {
    Step::result("getbestblockhash", json!([]), &quote(GENESIS))
}
fn outpoint() -> OutPoint {
    OutPoint::new(TXID.parse().unwrap(), 0)
}
fn txout(value: &str) -> String {
    format!(
        r#"{{"bestblock":"{GENESIS}","confirmations":1,"value":{value},"scriptPubKey":{{"asm":"","hex":"","type":"nonstandard"}},"version":1,"coinbase":true}}"#
    )
}
fn parent(confirmations: i64, blockhash: Option<&str>) -> String {
    format!(
        r#"{{"txid":"{TXID}","version":1,"locktime":0,"confirmations":{confirmations},"blockhash":{},"vout":[{{"n":0,"value":88.00000000,"scriptPubKey":{{"asm":"","hex":"","type":"nonstandard"}}}}]}}"#,
        blockhash.map_or("null".into(), quote)
    )
}

const FULL_BLOCK: &str = include_str!("fixtures/regtest-115-verbose.json");
const FULL_HASH: &str = "47ea9ba351b01055d60266eeccefa10f38be653b82d186a3c087366a038eed18";
const COINBASE: &str = "5fd1843277d6785d2f0aabc5134275a08c0438033889270ed97b4cc0d0f7a1d1";
const PAYMENT: &str = "91ad35ec9a22b3d1c451fea8523c4152eb875f2b6543ca573ba685af9d1949df";
fn block_with_tx(tx: &str) -> String {
    // Preserve original number tokens and extra Core fields in derived mode samples.
    let mut fields: std::collections::BTreeMap<String, Box<serde_json::value::RawValue>> =
        serde_json::from_str(FULL_BLOCK).unwrap();
    fields.insert("tx".into(), serde_json::from_str(tx).unwrap());
    serde_json::to_string(&fields).unwrap()
}
fn block_hashes() -> String {
    block_with_tx(&format!(r#"["{COINBASE}","{PAYMENT}"]"#))
}

#[tokio::test]
async fn block_selectors_resolve_height_full_and_latest_hashes_lazily() {
    let hashes = block_hashes();
    let server = Server::start(vec![
        Step::result("getblockhash", json!([115]), &quote(FULL_HASH)),
        Step::result("getblock", json!([FULL_HASH, 2]), FULL_BLOCK),
        Step::result("getbestblockhash", json!([]), &quote(FULL_HASH)),
        Step::result("getblock", json!([FULL_HASH, 1]), &hashes),
    ]);
    let p = Provider::new(transport(&server));
    // Unpolled selectors must leave the expected lookup/fetch sequence untouched.
    drop(p.get_block_by_height(115).full().into_future());
    drop(p.get_block(BlockId::Latest).into_future());
    let full = p.get_block_by_height(115).full().await.unwrap();
    assert_eq!(full.header.height, 115);
    assert_eq!(full.header.hash.to_string(), FULL_HASH);
    assert!(full.transactions.as_transactions().is_some());
    let latest = p.get_block(BlockId::Latest).await.unwrap();
    assert_eq!(latest.header.hash.to_string(), FULL_HASH);
    assert!(latest.transactions.as_hashes().is_some());
    assert_eq!(server.finish().len(), 4);
}

#[tokio::test]
async fn block_selectors_preflight_stop_on_lookup_error_and_check_height() {
    let server = Server::start(vec![
        Step::body(
            "getblockhash",
            json!([116]),
            500,
            r#"{"result":null,"error":{"code":-8,"message":"height out of range"},"id":$ID}"#,
        ),
        Step::result("getblockhash", json!([116]), &quote(FULL_HASH)),
        Step::result("getblock", json!([FULL_HASH, 2]), FULL_BLOCK),
        Step::result("getblockhash", json!([116]), &quote(FULL_HASH)),
        Step::result("getblock", json!([FULL_HASH, 1]), &block_hashes()),
    ]);
    let p = Provider::new(transport(&server));
    let legacy = p
        .clone()
        .with_block_verbosity(BlockVerbosity::LegacyBoolean);
    assert!(matches!(
        legacy.get_block_by_height(116).full().await,
        Err(Error::UnsupportedBlockVerbosity { .. })
    ));
    assert!(matches!(
        legacy.get_block(BlockId::Latest).full().await,
        Err(Error::UnsupportedBlockVerbosity { .. })
    ));
    assert!(matches!(
        p.get_block_by_height(116).full().await,
        Err(Error::Rpc { method, code: -8, .. }) if method == "getblockhash"
    ));
    // The resolved hash matches, but the returned header says height 115.
    assert!(matches!(
        p.get_block_by_height(116).full().await,
        Err(Error::InvalidResponse { method, .. }) if method == "getblock"
    ));
    assert!(matches!(
        p.get_block_by_height(116).await,
        Err(Error::InvalidResponse { method, .. }) if method == "getblock"
    ));
    assert_eq!(server.finish().len(), 5);
}

#[tokio::test]
async fn block_builder_default_and_full_preserve_core_fixture() {
    fn require_send<T: Send>(value: T) -> T {
        value
    }
    let hashes = block_hashes();
    let server = Server::start(vec![
        Step::result("getblock", json!([FULL_HASH, 1]), &hashes),
        Step::result("getblock", json!([FULL_HASH, 2]), FULL_BLOCK),
    ]);
    let p = Provider::new(transport(&server));
    let hash = FULL_HASH.parse().unwrap();
    // Dropping either unpolled mode must leave the server's two expected calls untouched.
    for request in [p.get_block_by_hash(hash), p.get_block_by_hash(hash).full()] {
        drop(require_send(require_send(request).into_future()));
    }
    let block = p.get_block_by_hash(hash).await.unwrap();
    assert_eq!(
        block.transactions.as_hashes().unwrap(),
        &[COINBASE.parse().unwrap(), PAYMENT.parse().unwrap()]
    );
    assert!(block.transactions.as_transactions().is_none());
    let full = require_send(p.get_block_by_hash(hash).full().into_future())
        .await
        .unwrap();
    assert_eq!(full.size, 659);
    assert_eq!(full.header.difficulty.as_str(), "4.656542373906925e-10");
    assert_eq!(
        full.header.chainwork,
        "00000000000000000000000000000000000000000000000000000000000000e8"
    );
    assert_eq!(full.transactions.len(), 2);
    assert!(!full.transactions.is_empty());
    assert!(full.transactions.as_hashes().is_none());
    let tx = full.transactions.as_transactions().unwrap();
    assert_eq!(
        [tx[0].txid.to_string(), tx[1].txid.to_string()],
        [COINBASE, PAYMENT]
    );
    assert!(tx.iter().all(|tx| tx.hex.is_none() && tx.weight.is_none()));
    assert!(
        matches!(&tx[0].vin[0].kind, TransactionInputKind::Coinbase { coinbase } if coinbase == "01730101")
    );
    assert_eq!(tx[0].vin[0].sequence, u32::MAX);
    assert!(tx[0].vin[0].script_sig.is_none());
    assert!(
        matches!(tx[1].vin[0].kind, TransactionInputKind::Spend { txid, vout: 1 } if txid.to_string() == "97fadce49693712ba823ee726dab962e1fc192c841411b8dd21611ea24ff746e")
    );
    assert_eq!(tx[1].vin[0].sequence, u32::MAX - 1);
    assert!(
        tx[1].vin[0]
            .script_sig
            .as_ref()
            .unwrap()
            .asm
            .contains("[ALL]")
    );
    let outputs: Vec<_> = tx
        .iter()
        .flat_map(|tx| &tx.vout)
        .map(|o| (o.n, o.value.koinu(), o.value.source_text()))
        .collect();
    assert_eq!(
        outputs,
        [
            (0, 50_000_000_226_000, "500000.00226000"),
            (1, 0, "0.00000000"),
            (0, 275_000_000, "2.75000000"),
            (1, 1_049_774_000, "10.49774000")
        ]
    );
    assert_eq!(server.finish().len(), 2);
}

#[tokio::test]
async fn block_builder_keeps_empty_modes_and_rejects_wrong_shapes() {
    let empty = block_with_tx("[]");
    let hashes = block_hashes();
    let mixed = block_with_tx(&format!(r#"["{COINBASE}",{{}}]"#));
    for (full, response, valid) in [
        (false, empty.as_str(), true),
        (true, empty.as_str(), true),
        (false, FULL_BLOCK, false),
        (true, hashes.as_str(), false),
        (false, mixed.as_str(), false),
    ] {
        let server = Server::start(vec![Step::result(
            "getblock",
            json!([FULL_HASH, if full { 2 } else { 1 }]),
            response,
        )]);
        let p = Provider::new(transport(&server));
        let request = p.get_block_by_hash(FULL_HASH.parse().unwrap());
        let result = if full {
            request.full().await
        } else {
            request.await
        };
        if valid {
            let tx = result.unwrap().transactions;
            assert!(tx.is_empty());
            assert_eq!(tx.len(), 0);
            assert!(matches!(
                (&tx, full),
                (BlockTransactions::Hashes(_), false) | (BlockTransactions::Full(_), true)
            ));
        } else {
            assert!(matches!(result, Err(Error::InvalidResponse { .. })));
        }
        server.finish();
    }
}

#[tokio::test]
async fn block_builder_legacy_full_is_local_and_hashes_keep_old_contract() {
    let hashes = block_hashes();
    let server = Server::start(
        (0..3)
            .map(|_| Step::result("getblock", json!([FULL_HASH, true]), &hashes))
            .collect(),
    );
    let p = Provider::new(transport(&server)).with_block_verbosity(BlockVerbosity::LegacyBoolean);
    let hash = FULL_HASH.parse().unwrap();
    let error = p.get_block_by_hash(hash).full().await.unwrap_err();
    assert!(matches!(
        error,
        Error::UnsupportedBlockVerbosity {
            verbosity: 2,
            mode: BlockVerbosity::LegacyBoolean
        }
    ));
    assert!(
        error
            .to_string()
            .contains("getblock verbosity 2 is unsupported in legacy boolean mode")
    );
    let default = p.get_block_by_hash(hash).await.unwrap();
    let reset = p.get_block_by_hash(hash).full().hashes().await.unwrap();
    let old = p.block_info(hash).await.unwrap();
    assert_eq!(default.transactions.as_hashes(), Some(old.tx.as_slice()));
    assert_eq!(reset.transactions.as_hashes(), Some(old.tx.as_slice()));
    assert_eq!(server.finish().len(), 3);
}

#[tokio::test]
async fn block_builder_rejects_wrong_hash_and_ambiguous_coinbase() {
    let hashes = block_hashes();
    let ambiguous = FULL_BLOCK.replacen(
        r#""coinbase": "01730101""#,
        &format!(r#""coinbase": "01730101", "txid": "{PAYMENT}", "vout": 0"#),
        1,
    );
    let server = Server::start(vec![
        Step::result("getblock", json!([GENESIS, 1]), &hashes),
        Step::result("getblock", json!([GENESIS, 2]), FULL_BLOCK),
        Step::result("getblock", json!([FULL_HASH, 2]), &ambiguous),
    ]);
    let p = Provider::new(transport(&server));
    for result in [
        p.get_block_by_hash(GENESIS.parse().unwrap()).await,
        p.get_block_by_hash(GENESIS.parse().unwrap()).full().await,
    ] {
        assert!(
            matches!(result, Err(Error::HashMismatch { expected, actual }) if expected.to_string() == GENESIS && actual.to_string() == FULL_HASH)
        );
    }
    assert!(matches!(
        p.get_block_by_hash(FULL_HASH.parse().unwrap()).full().await,
        Err(Error::InvalidResponse { .. })
    ));
    server.finish();
}

#[tokio::test]
async fn real_http_read_path_and_basic_auth() {
    let block = quote(&hex(BLOCK));
    let server = Server::start(vec![
        Step::result("getblockchaininfo", json!([]), &chain_info("regtest")),
        Step::result("getblockhash", json!([0]), &quote(GENESIS)),
        Step::result("getblockhash", json!([0]), &quote(GENESIS)),
        Step::result("getblock", json!([GENESIS, 0]), &block),
        Step::result("getblockhash", json!([0]), &quote(GENESIS)),
    ]);
    let provider = Provider::new(transport(&server));
    let info = provider.validate_network(Network::Regtest).await.unwrap();
    assert_eq!(info.verificationprogress.as_str(), "0.99999999999999999");
    let check = provider.check_block_at_height(0).await.unwrap();
    assert_eq!(check.block_hash.to_string(), GENESIS);
    assert_eq!(check.byte_len, BLOCK.len());
    for (i, captured) in server.finish().iter().enumerate() {
        assert_eq!(captured["request"]["id"], i + 1);
        assert!(
            captured["headers"]
                .as_str()
                .unwrap()
                .contains("Basic dXNlcjpwYXNz")
        );
    }
}
#[tokio::test]
async fn raw_and_verbose_headers_and_blocks_are_distinct() {
    let verbose = header(GENESIS);
    let block_verbose = verbose.trim_end_matches('}').to_string()
        + &format!(r#", "size":{},"tx":["{TXID}"]}}"#, BLOCK.len());
    let server = Server::start(vec![
        Step::result(
            "getblockheader",
            json!([GENESIS, false]),
            &quote(&hex(&BLOCK[..80])),
        ),
        Step::result("getblockheader", json!([GENESIS, true]), &verbose),
        Step::result("getblock", json!([GENESIS, 1]), &block_verbose),
    ]);
    let p = Provider::new(transport(&server));
    assert_eq!(
        p.raw_block_header(GENESIS.parse().unwrap()).await.unwrap(),
        &BLOCK[..80]
    );
    assert_eq!(
        p.block_header(GENESIS.parse().unwrap())
            .await
            .unwrap()
            .difficulty
            .as_str(),
        "1.00000000000000001e-8"
    );
    let info = p.block_info(GENESIS.parse().unwrap()).await.unwrap();
    assert_eq!(info.tx[0].to_string(), TXID);
    assert_eq!(info.header.difficulty.as_str(), "1.00000000000000001e-8");
    server.finish();
}
#[tokio::test]
async fn auxpow_header_requires_complete_payload_but_base_remains_usable() {
    let server = Server::start(vec![
        Step::result(
            "getblockheader",
            json!([AUX_HASH, false]),
            &quote(&hex(&AUX_BLOCK[..80])),
        ),
        Step::result(
            "getblockheader",
            json!([AUX_HASH, false]),
            &quote(&hex(&AUX_BLOCK[..80])),
        ),
        Step::result(
            "getblockheader",
            json!([AUX_HASH, false]),
            &quote(&hex(&AUX_BLOCK[..297])),
        ),
    ]);
    let p = Provider::new(transport(&server));
    assert!(matches!(
        p.raw_block_header(AUX_HASH.parse().unwrap()).await,
        Err(Error::InvalidResponse { .. })
    ));
    assert_eq!(
        p.base_block_header(AUX_HASH.parse().unwrap())
            .await
            .unwrap()
            .block_id()
            .to_string(),
        AUX_HASH
    );
    assert_eq!(
        p.raw_block_header(AUX_HASH.parse().unwrap())
            .await
            .unwrap()
            .len(),
        297
    );
    server.finish();
}
#[tokio::test]
async fn legacy_boolean_is_explicit_and_never_replayed_on_error() {
    let server = Server::start(vec![
        Step::result("getblock", json!([GENESIS, false]), &quote(&hex(BLOCK))),
        Step::body(
            "getblock",
            json!([GENESIS, 0]),
            500,
            r#"{"result":null,"error":{"code":-8,"message":"unsupported verbosity"},"id":$ID}"#,
        ),
    ]);
    let p = Provider::new(transport(&server)).with_block_verbosity(BlockVerbosity::LegacyBoolean);
    assert_eq!(p.raw_block(GENESIS.parse().unwrap()).await.unwrap(), BLOCK);
    // Numeric mode reports the node's rejection; it must not guess a boolean fallback.
    let numeric = Provider::new(transport(&server));
    assert!(matches!(
        numeric.raw_block(GENESIS.parse().unwrap()).await,
        Err(Error::Rpc { code: -8, .. })
    ));
    assert_eq!(server.finish().len(), 2);
}
#[tokio::test]
async fn structured_core_errors_survive_non_success_statuses() {
    for status in [200, 500, 503] {
        let server = Server::start(vec![Step::body(
            "getblockcount",
            json!([]),
            status,
            r#"{"result":null,"error":{"code":-28,"message":"Loading block index","data":{"attempt":9007199254740993}},"id":$ID}"#,
        )]);
        let error = Provider::new(transport(&server))
            .block_count()
            .await
            .unwrap_err();
        match error {
            Error::Rpc {
                method,
                code,
                message,
                data,
                status: s,
            } => {
                assert_eq!(method, "getblockcount");
                assert_eq!(code, -28);
                assert_eq!(message, "Loading block index");
                assert_eq!(s, status);
                assert_eq!(data.unwrap().get(), r#"{"attempt":9007199254740993}"#);
            }
            other => panic!("{other:?}"),
        }
        server.finish();
    }
}
#[tokio::test]
async fn rejects_wrong_missing_duplicate_and_malformed_envelopes() {
    for body in [
        r#"{"result":1,"error":null,"id":99}"#,
        r#"{"result":1,"error":null,"id":"1"}"#,
        r#"{"result":1,"error":null,"id":null}"#,
        r#"{"result":1,"error":null}"#,
        r#"{"error":null,"id":$ID}"#,
        r#"{"result":1,"id":$ID}"#,
        r#"{"result":1,"error":null,"id":$ID,"id":$ID}"#,
        r#"{"result":1,"error":{"code":-1,"message":"bad"},"id":$ID}"#,
        r#"{"result":null,"error":{"code":"bad","message":"bad"},"id":$ID}"#,
        r#"{"result":"wrong type","error":null,"id":$ID}"#,
        "not json",
    ] {
        let server = Server::start(vec![Step::body("getblockcount", json!([]), 200, body)]);
        assert!(
            matches!(
                Provider::new(transport(&server)).block_count().await,
                Err(Error::InvalidResponse { .. })
            ),
            "{body}"
        );
        server.finish();
    }
}
#[tokio::test]
async fn http_errors_without_envelopes_remain_http_errors() {
    for (status, body) in [
        (401, "Unauthorized"),
        (500, r#"{"result":1,"error":null,"id":$ID}"#),
    ] {
        let server = Server::start(vec![Step::body("getblockcount", json!([]), status, body)]);
        assert!(
            matches!(Provider::new(transport(&server)).block_count().await,Err(Error::HttpStatus{status:s}) if s==status)
        );
        server.finish();
    }
}
#[tokio::test]
async fn real_null_exact_money_and_mempool_responses() {
    let server = Server::start(vec![
        Step::result("gettxout", json!([TXID, 0, false]), "null"),
        Step::result("gettxout", json!([TXID, 0, true]), &txout("1e-8")),
        Step::result("getrawmempool", json!([false]), &format!(r#"["{TXID}"]"#)),
        Step::result(
            "getmempoolinfo",
            json!([]),
            r#"{"size":1,"bytes":100,"usage":200,"mempoolminfee":0.00000001}"#,
        ),
    ]);
    let p = Provider::new(transport(&server));
    assert!(
        p.tx_out(outpoint(), SpendView::ConfirmedOnly)
            .await
            .unwrap()
            .is_none()
    );
    let output = p
        .tx_out(outpoint(), SpendView::IncludeMempool)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(output.value.koinu(), 1);
    assert_eq!(output.value.source_text(), "1e-8");
    assert_eq!(p.raw_mempool().await.unwrap()[0].to_string(), TXID);
    assert_eq!(
        p.mempool_info()
            .await
            .unwrap()
            .mempoolminfee
            .unwrap()
            .koinu(),
        1
    );
    server.finish();
}
#[tokio::test]
async fn exact_money_rejection_occurs_at_real_http_boundary() {
    for value in [
        "0.0000000100",
        "184467440737.09551616",
        "1e2147483648",
        "0e-2147483649",
        "-0.1",
    ] {
        let server = Server::start(vec![Step::result(
            "gettxout",
            json!([TXID, 0, true]),
            &txout(value),
        )]);
        assert!(matches!(
            Provider::new(transport(&server))
                .tx_out(outpoint(), SpendView::IncludeMempool)
                .await,
            Err(Error::InvalidResponse { .. })
        ));
        server.finish();
    }
}
#[tokio::test]
async fn response_limit_checks_declared_chunked_and_exact_boundary() {
    let body = r#"{"result":7,"error":null,"id":1}"#;
    for (limit, chunked, declared, success) in [
        (body.len(), false, None, true),
        (body.len() - 1, false, None, false),
        (body.len() - 1, true, None, false),
        (32, false, Some(1_000_000), false),
    ] {
        let mut step = Step::body("getblockcount", json!([]), 200, body);
        step.chunked = chunked;
        step.declared_length = declared;
        let server = Server::start(vec![step]);
        let client = Client::with_config(
            transport(&server),
            ClientConfig {
                max_response_bytes: limit,
            },
        );
        let result = client.call::<_, u64>("getblockcount", json!([])).await;
        if success {
            assert_eq!(result.unwrap(), 7);
        } else {
            assert!(
                matches!(result,Err(Error::Transport(TransportError::ResponseTooLarge{limit:l})) if l==limit)
            );
        }
        server.finish();
    }
}
#[tokio::test]
async fn ids_are_shared_between_client_clones() {
    let server = Server::start(vec![
        Step::result("getblockcount", json!([]), "1"),
        Step::result("getblockcount", json!([]), "2"),
    ]);
    let first = Client::new(transport(&server));
    let second = first.clone();
    assert_eq!(
        first
            .call::<_, u64>("getblockcount", json!([]))
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        second
            .call::<_, u64>("getblockcount", json!([]))
            .await
            .unwrap(),
        2
    );
    let requests = server.finish();
    assert_eq!(requests[0]["request"]["id"], 1);
    assert_eq!(requests[1]["request"]["id"], 2);
}
#[tokio::test]
async fn network_identity_checks_both_chain_name_and_genesis() {
    for (chain, genesis) in [("main", GENESIS), ("regtest", TXID)] {
        let server = Server::start(vec![
            Step::result("getblockchaininfo", json!([]), &chain_info(chain)),
            Step::result("getblockhash", json!([0]), &quote(genesis)),
        ]);
        assert!(matches!(
            Provider::new(transport(&server))
                .validate_network(Network::Regtest)
                .await,
            Err(Error::NetworkMismatch { .. })
        ));
        server.finish();
    }
}
#[tokio::test]
async fn changed_anchor_prevents_success() {
    let server = Server::start(vec![
        Step::result("getblockhash", json!([0]), &quote(GENESIS)),
        Step::result("getblock", json!([GENESIS, 0]), &quote(&hex(BLOCK))),
        Step::result("getblockhash", json!([0]), &quote(TXID)),
    ]);
    assert!(matches!(
        Provider::new(transport(&server))
            .check_block_at_height(0)
            .await,
        Err(Error::AnchorChanged { height: 0, .. })
    ));
    server.finish();
}
#[tokio::test]
async fn wrong_hash_and_bad_hex_are_rejected() {
    for result in [quote("nothex"), quote("0"), quote(&hex(BLOCK))] {
        let server = Server::start(vec![Step::result("getblock", json!([TXID, 0]), &result)]);
        assert!(
            Provider::new(transport(&server))
                .raw_block(TXID.parse().unwrap())
                .await
                .is_err()
        );
        server.finish();
    }
}
#[tokio::test]
async fn utxo_null_is_unknown_when_parent_is_unavailable() {
    let server = Server::start(vec![
        tip(),
        Step::result("gettxout", json!([TXID, 0, false]), "null"),
        Step::body(
            "getrawtransaction",
            json!([TXID, true]),
            500,
            r#"{"result":null,"error":{"code":-5,"message":"No such transaction"},"id":$ID}"#,
        ),
        tip(),
    ]);
    let status = Provider::new(transport(&server))
        .utxo_status(outpoint(), SpendView::ConfirmedOnly)
        .await
        .unwrap();
    assert!(matches!(
        status.status,
        UtxoStatus::Unknown(UtxoUnknown::ParentUnavailable)
    ));
    server.finish();
}
#[tokio::test]
async fn confirmed_spent_requires_parent_active_chain_evidence() {
    let server = Server::start(vec![
        tip(),
        Step::result("gettxout", json!([TXID, 0, false]), "null"),
        Step::result(
            "getrawtransaction",
            json!([TXID, true]),
            &parent(1, Some(GENESIS)),
        ),
        Step::result("getblockheader", json!([GENESIS, true]), &header(GENESIS)),
        Step::result("getblockhash", json!([0]), &quote(GENESIS)),
        tip(),
    ]);
    let status = Provider::new(transport(&server))
        .utxo_status(outpoint(), SpendView::ConfirmedOnly)
        .await
        .unwrap();
    assert!(
        matches!(status.status,UtxoStatus::Spent{parent_block:Some(hash)} if hash.to_string()==GENESIS)
    );
    server.finish();
}
#[tokio::test]
async fn confirmed_view_does_not_classify_unconfirmed_parent_as_spent() {
    let server = Server::start(vec![
        tip(),
        Step::result("gettxout", json!([TXID, 0, false]), "null"),
        Step::result("getrawtransaction", json!([TXID, true]), &parent(0, None)),
        tip(),
    ]);
    let status = Provider::new(transport(&server))
        .utxo_status(outpoint(), SpendView::ConfirmedOnly)
        .await
        .unwrap();
    assert!(matches!(
        status.status,
        UtxoStatus::Unknown(UtxoUnknown::ParentNotActive)
    ));
    server.finish();
}
#[tokio::test]
async fn utxo_observation_rejects_tip_drift() {
    let server = Server::start(vec![
        tip(),
        Step::result("gettxout", json!([TXID, 0, true]), &txout("1")),
        Step::result("getbestblockhash", json!([]), &quote(TXID)),
    ]);
    assert!(matches!(
        Provider::new(transport(&server))
            .utxo_status(outpoint(), SpendView::IncludeMempool)
            .await,
        Err(Error::TipChanged { .. })
    ));
    server.finish();
}
#[test]
fn credentials_and_unsupported_endpoints_are_redacted() {
    let auth = BasicAuth::new("private-user", "private-password");
    let t = HttpTransport::new(
        "http://127.0.0.1/private-wallet",
        Some(auth.clone()),
        HttpConfig::default(),
    )
    .unwrap();
    let debug = format!("{auth:?} {t:?} {:?}", Client::new(t.clone()));
    for secret in ["private-user", "private-password", "private-wallet"] {
        assert!(!debug.contains(secret));
    }
    for url in [
        "https://secret:password@localhost",
        "ftp://localhost",
        "http://secret:password@localhost",
        "http://localhost/?token=secret",
    ] {
        let error = HttpTransport::new(url, None, HttpConfig::default()).unwrap_err();
        assert!(!format!("{error:?} {error}").contains("secret"));
    }
}
#[tokio::test]
async fn redirects_are_not_followed_or_downgraded() {
    let mut step = Step::body("getblockcount", json!([]), 302, "redirect");
    step.extra_header = "Location: https://127.0.0.1:1/secret\r\n".into();
    let server = Server::start(vec![step]);
    assert!(matches!(
        Provider::new(transport(&server)).block_count().await,
        Err(Error::HttpStatus { status: 302 })
    ));
    server.finish();
}
#[tokio::test]
async fn broadcast_timeout_is_unknown_and_no_replay_occurs() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let server = thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(3);
        let mut stream = loop {
            if let Ok((s, _)) = listener.accept() {
                break s;
            }
            assert!(Instant::now() < deadline);
            thread::sleep(Duration::from_millis(2));
        };
        let (_, request) = read_request(&mut stream);
        assert_eq!(request["method"], "sendrawtransaction");
        let until = Instant::now() + Duration::from_millis(200);
        let mut count = 1;
        while Instant::now() < until {
            if listener.accept().is_ok() {
                count += 1
            }
            thread::sleep(Duration::from_millis(2));
        }
        let _ = stream.write_all(b"");
        count
    });
    let config = HttpConfig {
        request_timeout: Duration::from_millis(50),
        ..Default::default()
    };
    let p = Provider::new(HttpTransport::new(&url, None, config).unwrap());
    let error = p.broadcast(&BLOCK[81..]).await.unwrap_err();
    assert!(
        matches!(error,Error::SubmissionUnknown{txid,cause} if txid.to_string()==TXID && matches!(*cause,Error::Transport(TransportError::Timeout)))
    );
    assert_eq!(server.join().unwrap(), 1);
}
#[tokio::test]
async fn broadcast_reconciles_returned_txid_and_preserves_rejections() {
    for (result, expected) in [(TXID, true), (GENESIS, false)] {
        let server = Server::start(vec![Step::result(
            "sendrawtransaction",
            json!([hex(&BLOCK[81..])]),
            &quote(result),
        )]);
        let response = Provider::new(transport(&server))
            .broadcast(&BLOCK[81..])
            .await;
        if expected {
            assert_eq!(response.unwrap().to_string(), TXID);
        } else {
            assert!(matches!(response, Err(Error::BroadcastTxidMismatch { .. })));
        }
        server.finish();
    }
    let server = Server::start(vec![Step::body(
        "sendrawtransaction",
        json!([hex(&BLOCK[81..])]),
        500,
        r#"{"result":null,"error":{"code":-26,"message":"rejected"},"id":$ID}"#,
    )]);
    assert!(matches!(
        Provider::new(transport(&server))
            .broadcast(&BLOCK[81..])
            .await,
        Err(Error::Rpc { code: -26, .. })
    ));
    server.finish();
}
#[tokio::test]
async fn typed_general_chain_and_transaction_reads_use_core_parameters() {
    let raw_tx = &BLOCK[81..];
    let server = Server::start(vec![
        Step::result(
            "getnetworkinfo",
            json!([]),
            r#"{"version":1140900,"subversion":"/Shibetoshi:1.14.9/","protocolversion":70015,"connections":0,"relayfee":0.00100000}"#,
        ),
        Step::result(
            "getchaintips",
            json!([]),
            &format!(r#"[{{"height":0,"hash":"{GENESIS}","branchlen":0,"status":"active"}}]"#),
        ),
        Step::result(
            "getrawtransaction",
            json!([TXID, false]),
            &quote(&hex(raw_tx)),
        ),
        Step::result(
            "getrawtransaction",
            json!([TXID, true]),
            &parent(1, Some(GENESIS)),
        ),
        Step::result(
            "decoderawtransaction",
            json!([hex(raw_tx)]),
            &parent(0, None),
        ),
        Step::result(
            "getmempoolentry",
            json!([TXID]),
            r#"{"size":123,"fee":0.00000001,"time":123456,"height":1,"depends":[]}"#,
        ),
    ]);
    let p = Provider::new(transport(&server));
    assert_eq!(p.network_info().await.unwrap().relayfee.koinu(), 100_000);
    assert_eq!(p.chain_tips().await.unwrap()[0].status, "active");
    assert_eq!(
        p.raw_transaction(TXID.parse().unwrap()).await.unwrap(),
        raw_tx
    );
    assert_eq!(
        p.transaction_info(TXID.parse().unwrap())
            .await
            .unwrap()
            .vout[0]
            .value
            .koinu(),
        8_800_000_000
    );
    assert_eq!(
        p.decode_transaction(raw_tx).await.unwrap().txid.to_string(),
        TXID
    );
    assert_eq!(
        p.mempool_entry(TXID.parse().unwrap())
            .await
            .unwrap()
            .fee
            .koinu(),
        1
    );
    server.finish();
}
#[tokio::test]
async fn null_with_invalid_output_index_stays_unknown() {
    let server = Server::start(vec![
        tip(),
        Step::result("gettxout", json!([TXID, 9, true]), "null"),
        Step::result(
            "getrawtransaction",
            json!([TXID, true]),
            &parent(1, Some(GENESIS)),
        ),
        tip(),
    ]);
    let status = Provider::new(transport(&server))
        .utxo_status(
            OutPoint::new(TXID.parse().unwrap(), 9),
            SpendView::IncludeMempool,
        )
        .await
        .unwrap();
    assert!(matches!(
        status.status,
        UtxoStatus::Unknown(UtxoUnknown::InvalidOutputIndex)
    ));
    server.finish();
}
#[tokio::test]
async fn mempool_parent_spend_and_eviction_remain_distinct() {
    for present in [true, false] {
        let entry = if present {
            Step::result(
                "getmempoolentry",
                json!([TXID]),
                r#"{"size":100,"fee":0.01,"time":1000,"height":1}"#,
            )
        } else {
            Step::body(
                "getmempoolentry",
                json!([TXID]),
                500,
                r#"{"result":null,"error":{"code":-5,"message":"not in mempool"},"id":$ID}"#,
            )
        };
        let server = Server::start(vec![
            tip(),
            Step::result("gettxout", json!([TXID, 0, true]), "null"),
            Step::result("getrawtransaction", json!([TXID, true]), &parent(0, None)),
            entry,
            tip(),
        ]);
        let status = Provider::new(transport(&server))
            .utxo_status(outpoint(), SpendView::IncludeMempool)
            .await
            .unwrap();
        if present {
            assert!(matches!(
                status.status,
                UtxoStatus::Spent { parent_block: None }
            ));
        } else {
            assert!(matches!(
                status.status,
                UtxoStatus::Unknown(UtxoUnknown::ParentNotObservedInMempool)
            ));
        }
        server.finish();
    }
}
#[tokio::test]
async fn stale_parent_is_not_classified_as_confirmed_spent() {
    let server = Server::start(vec![
        tip(),
        Step::result("gettxout", json!([TXID, 0, false]), "null"),
        Step::result(
            "getrawtransaction",
            json!([TXID, true]),
            &parent(-1, Some(GENESIS)),
        ),
        tip(),
    ]);
    let status = Provider::new(transport(&server))
        .utxo_status(outpoint(), SpendView::ConfirmedOnly)
        .await
        .unwrap();
    assert!(matches!(
        status.status,
        UtxoStatus::Unknown(UtxoUnknown::ParentNotActive)
    ));
    server.finish();
}
#[tokio::test]
async fn stable_tip_bracket_keeps_unspent_output_and_view() {
    let server = Server::start(vec![
        tip(),
        Step::result("gettxout", json!([TXID, 0, false]), &txout("88.00000000")),
        tip(),
    ]);
    let observation = Provider::new(transport(&server))
        .utxo_status(outpoint(), SpendView::ConfirmedOnly)
        .await
        .unwrap();
    assert_eq!(observation.view, SpendView::ConfirmedOnly);
    assert_eq!(observation.tip.to_string(), GENESIS);
    assert!(
        matches!(observation.status,UtxoStatus::Unspent(ref value) if value.value.koinu()==8_800_000_000)
    );
    server.finish();
}
#[tokio::test]
async fn transport_ceiling_still_applies_to_explicit_larger_call_budgets() {
    let server = Server::start(vec![Step::result("getblockcount", json!([]), "7")]);
    let transport = HttpTransport::new(
        &server.url,
        None,
        HttpConfig {
            max_response_bytes: 8,
            ..Default::default()
        },
    )
    .unwrap();
    let result = Client::new(transport)
        .call_with_response_limit::<_, u64>("getblockcount", json!([]), 1024)
        .await;
    assert!(matches!(
        result,
        Err(Error::Transport(TransportError::ResponseTooLarge {
            limit: 8
        }))
    ));
    server.finish();
}
