//! Independent Core wire contracts: literal decimal tokens, positional requests,
//! complete snapshots and exactly one attempted mutation even on ambiguous errors.
use planchet_provider::transport::{self, Request, Response, Transport, TransportFuture};
use planchet_provider::types::wallet::{
    ImportTimestamp, RpcSignedAmount, WalletInfo, WalletScanning, WatchImport,
};
use planchet_provider::wallet::{LIST_UNSPENT_MAXCONF, MAX_LISTUNSPENT_RESPONSE_BYTES};
use planchet_provider::{Client, Error, Provider, SnapshotLimits};
use serde_json::{Value, json};
use std::{
    collections::VecDeque,
    sync::{Arc, Mutex},
};

const HASH: &str = "0000000000000000000000000000000000000000000000000000000000000001";
const UNSPENT: &str = r#"{"txid":"0000000000000000000000000000000000000000000000000000000000000001","vout":2,"address":"watch","scriptPubKey":"51","amount":1e-8,"confirmations":3,"spendable":false,"solvable":true}"#;
const WALLET: &str = r#"{"walletversion":130000,"balance":1.00000001,"unconfirmed_balance":0.00000000,"immature_balance":0,"txcount":2,"keypoololdest":1,"keypoolsize":100,"paytxfee":0.01000000}"#;

#[derive(Debug)]
struct Call {
    method: String,
    params: Value,
    limit: usize,
}
type Reply = Result<(u16, String, String), transport::Error>;
#[derive(Clone)]
struct Mock {
    calls: Arc<Mutex<Vec<Call>>>,
    replies: Arc<Mutex<VecDeque<Reply>>>,
}
impl Mock {
    fn results(results: &[&str]) -> Self {
        Self {
            calls: Arc::default(),
            replies: Arc::new(Mutex::new(
                results
                    .iter()
                    .map(|s| Ok((200, (*s).into(), "null".into())))
                    .collect(),
            )),
        }
    }
    fn fault(code: i64, message: &str) -> Self {
        Self {
            calls: Arc::default(),
            replies: Arc::new(Mutex::new(VecDeque::from([Ok((
                500,
                "null".into(),
                json!({"code":code,"message":message,"data":{"source":"node"}}).to_string(),
            ))]))),
        }
    }
    fn timeout() -> Self {
        Self {
            calls: Arc::default(),
            replies: Arc::new(Mutex::new(VecDeque::from([Err(transport::Error::Timeout)]))),
        }
    }
}
impl Transport for Mock {
    fn send(&self, request: Request) -> TransportFuture<'_> {
        Box::pin(async move {
            let request_body: Value = serde_json::from_slice(&request.body).unwrap();
            self.calls.lock().unwrap().push(Call {
                method: request_body["method"].as_str().unwrap().into(),
                params: request_body["params"].clone(),
                limit: request.max_response_bytes,
            });
            let (status, result, error) = self
                .replies
                .lock()
                .unwrap()
                .pop_front()
                .expect("unexpected extra request (replay)")?;
            let body = format!(
                r#"{{"id":{},"result":{},"error":{}}}"#,
                request_body["id"], result, error
            )
            .into_bytes();
            Ok(Response { status, body })
        })
    }
}

// Expected integers follow decimal-place arithmetic and i64 boundaries, not a
// floating point parser or a second copy of the implementation algorithm.
#[test]
fn signed_wallet_amounts_are_exact_and_roundtrip_source_tokens() {
    for (text, expected) in [
        ("-1e-8", -1),
        ("-0.00000000", 0),
        ("1.23456789", 123_456_789),
        ("-90071992.54740993", -9_007_199_254_740_993),
        ("92233720368.54775807", i64::MAX),
        ("-92233720368.54775808", i64::MIN),
    ] {
        let amount: RpcSignedAmount = serde_json::from_str(text).unwrap();
        assert_eq!(amount.koinu(), expected);
        assert_eq!(amount.source_text(), text);
        assert_eq!(serde_json::to_string(&amount).unwrap(), text);
    }
    for bad in [
        "92233720368.54775808",
        "-92233720368.54775809",
        "1e-9",
        "-0.000000001",
        "\"1\"",
        "true",
        "null",
        "1e999999999999999999999",
    ] {
        assert!(
            serde_json::from_str::<RpcSignedAmount>(bad).is_err(),
            "{bad}"
        );
    }
}

// Protect against silently replacing unavailable status with scanning=false.
#[test]
fn absent_wallet_scan_status_is_unknown_and_progress_keeps_decimal_token() {
    let wallet: WalletInfo = serde_json::from_str(WALLET).unwrap();
    assert!(wallet.scanning.is_none());
    assert_eq!(wallet.balance.koinu(), 100_000_001);
    let scanning = WALLET.trim_end_matches('}').to_string()
        + r#", "scanning":{"duration":7,"progress":0.1234567890123456789}}"#;
    match serde_json::from_str::<WalletInfo>(&scanning)
        .unwrap()
        .scanning
        .unwrap()
    {
        WalletScanning::Progress { duration, progress } => {
            assert_eq!(duration, 7);
            assert_eq!(progress.as_str(), "0.1234567890123456789");
        }
        _ => panic!("expected progress"),
    }
}

#[tokio::test]
async fn validation_and_imports_preserve_core_parameters_and_partial_results() {
    let mock = Mock::results(&[
        r#"{"isvalid":true,"ismine":false,"iswatchonly":true,"timestamp":123}"#,
        "null",
        "null",
        r#"[{"success":true,"warnings":["already watched"]},{"success":false,"error":{"code":-5,"message":"Invalid address"},"warnings":["not imported"]}]"#,
    ]);
    let rpc = Provider::new(mock.clone());
    let address = rpc.validate_address("watch").await.unwrap();
    assert_eq!(address.iswatchonly, Some(true));
    assert_eq!(address.timestamp, Some(123));
    rpc.import_address("watch", Some("bridge"), false, false, None)
        .await
        .unwrap();
    rpc.import_address("51", None, true, true, Some(42))
        .await
        .unwrap();
    let mut first = WatchImport::address("watch", ImportTimestamp::Unix(123));
    first.label = Some("bridge".into());
    let second = WatchImport::address("bad", ImportTimestamp::Now);
    let results = rpc.import_multi(&[first, second], false).await.unwrap();
    assert!(results[0].success);
    assert_eq!(results[0].warnings, ["already watched"]);
    assert!(!results[1].success);
    assert_eq!(results[1].error.as_ref().unwrap().code, -5);
    assert_eq!(results[1].warnings, ["not imported"]);
    let calls = mock.calls.lock().unwrap();
    assert_eq!(calls.len(), 4);
    assert_eq!(calls[0].params, json!(["watch"]));
    assert_eq!(calls[1].params, json!(["watch", "bridge", false, false]));
    assert_eq!(calls[2].params, json!(["51", "", true, true, 42]));
    assert_eq!(calls[3].method, "importmulti");
    assert_eq!(
        calls[3].params,
        json!([
            [{"scriptPubKey":{"address":"watch"},"timestamp":123,"watchonly":true,"label":"bridge"},
             {"scriptPubKey":{"address":"bad"},"timestamp":"now","watchonly":true}], {"rescan":false}
        ])
    );
}

#[tokio::test]
async fn wallet_listings_keep_signed_deltas_conflicts_and_pagination() {
    let tx = format!(
        r#"{{"txid":"{HASH}","category":"send","amount":-90071992.54740993,"fee":-1e-8,"confirmations":-2,"involvesWatchonly":true}}"#
    );
    let since = format!(r#"{{"transactions":[{tx}],"lastblock":"{HASH}"}}"#);
    let received = format!(
        r#"[{{"address":"watch","amount":1e-8,"confirmations":0,"txids":["{HASH}"],"involvesWatchonly":true}}]"#
    );
    let page = format!(r#"[{tx},{{"category":"move","amount":-0.1,"otheraccount":"change"}}]"#);
    let mock = Mock::results(&[&since, &since, &received, &page]);
    let rpc = Provider::new(mock.clone());
    let result = rpc
        .list_since_block(Some(HASH.parse().unwrap()), 7, true)
        .await
        .unwrap();
    assert_eq!(
        result.transactions[0].amount.koinu(),
        -9_007_199_254_740_993
    );
    assert_eq!(result.transactions[0].fee.as_ref().unwrap().koinu(), -1);
    assert_eq!(result.transactions[0].confirmations, Some(-2));
    rpc.list_since_block(None, 1, true).await.unwrap();
    let received = rpc.list_received_by_address(0, true, true).await.unwrap();
    assert_eq!(received[0].amount.koinu(), 1);
    assert_eq!(received[0].involves_watchonly, Some(true));
    let page = rpc.list_transactions("*", 2, 17, true).await.unwrap();
    assert!(page[1].txid.is_none());
    let calls = mock.calls.lock().unwrap();
    assert_eq!(calls[0].method, "listsinceblock");
    assert_eq!(calls[0].params, json!([HASH, 7, true]));
    assert_eq!(calls[1].params, json!([null, 1, true]));
    assert_eq!(calls[2].method, "listreceivedbyaddress");
    assert_eq!(calls[2].params, json!([0, true, true]));
    assert_eq!(calls[3].method, "listtransactions");
    assert_eq!(calls[3].params, json!(["*", 2, 17, true]));
    assert!(calls.iter().all(|c| c.limit == 64 * 1024 * 1024));
}

// Protect reconciliation from marking omitted dust outputs spent: no amount or
// count query restrictions, explicit maxconf, full result, isolated byte budget.
#[tokio::test]
async fn complete_snapshot_has_separate_one_gib_budget_and_keeps_dust() {
    let unspent = format!("[{UNSPENT},{UNSPENT}]");
    let mock = Mock::results(&[&unspent, r#"{"isvalid":false}"#, "[]"]);
    let rpc = Provider::new(mock.clone());
    let addresses = vec!["watch".into()];
    let snapshot = rpc
        .list_unspent(
            0,
            LIST_UNSPENT_MAXCONF,
            &addresses,
            SnapshotLimits::default(),
        )
        .await
        .unwrap();
    assert_eq!(snapshot.outputs.len(), 2);
    assert_eq!(snapshot.outputs[0].amount.koinu(), 1);
    assert!(!snapshot.outputs[0].spendable);
    assert_eq!(snapshot.addresses, addresses);
    assert!(snapshot.include_unsafe);
    assert_eq!(snapshot.max_confirmations, i32::MAX as u64);
    rpc.validate_address("bad").await.unwrap();
    let confirmed = rpc
        .list_unspent_with_unsafe(1, 9_999_999, &[], false, SnapshotLimits::default())
        .await
        .unwrap();
    assert!(!confirmed.include_unsafe);
    let calls = mock.calls.lock().unwrap();
    assert_eq!(
        calls[0].params,
        json!([0, 2_147_483_647u64, ["watch"], true])
    );
    assert_eq!(calls[0].limit, 1024 * 1024 * 1024);
    assert_eq!(calls[1].limit, 64 * 1024 * 1024);
    assert_eq!(calls[2].params, json!([1, 9_999_999, [], false]));
}

#[tokio::test]
async fn capped_or_malformed_snapshots_fail_instead_of_returning_a_prefix() {
    let two = format!("[{UNSPENT},{UNSPENT}]");
    let mock = Mock::results(&[&two, "null", "[{}]", &two]);
    let rpc = Provider::new(mock.clone());
    let limits = SnapshotLimits {
        max_response_bytes: 4096,
        max_entries: 1,
    };
    for _ in 0..3 {
        assert!(matches!(
            rpc.list_unspent(0, 10, &[], limits).await,
            Err(Error::InvalidResponse { .. })
        ));
    }
    let tiny = SnapshotLimits {
        max_response_bytes: 50,
        max_entries: 10,
    };
    assert!(matches!(
        rpc.list_unspent(0, 10, &[], tiny).await,
        Err(Error::Transport(transport::Error::ResponseTooLarge {
            limit: 50
        }))
    ));
    let requests_sent = mock.calls.lock().unwrap().len();
    for bad in [
        SnapshotLimits {
            max_response_bytes: MAX_LISTUNSPENT_RESPONSE_BYTES + 1,
            max_entries: 1,
        },
        SnapshotLimits {
            max_response_bytes: 0,
            max_entries: 1,
        },
        SnapshotLimits {
            max_response_bytes: 1024,
            max_entries: 0,
        },
    ] {
        assert!(rpc.list_unspent(0, 10, &[], bad).await.is_err());
    }
    assert!(rpc.list_unspent(20, 10, &[], limits).await.is_err());
    assert!(
        rpc.list_unspent(0, LIST_UNSPENT_MAXCONF + 1, &[], limits)
            .await
            .is_err()
    );
    assert_eq!(mock.calls.lock().unwrap().len(), requests_sent);
}

#[tokio::test]
async fn inconsistent_import_results_fail_without_retry_or_fallback() {
    for result in [
        "[]",
        r#"[{"success":true,"error":{"code":-1,"message":"contradiction"}}]"#,
        r#"[{"success":false}]"#,
    ] {
        let mock = Mock::results(&[result]);
        let rpc = Provider::new(mock.clone());
        assert!(matches!(
            rpc.import_multi(
                &[WatchImport::address("watch", ImportTimestamp::Now)],
                false
            )
            .await,
            Err(Error::InvalidResponse { .. })
        ));
        assert_eq!(mock.calls.lock().unwrap().len(), 1);
    }
}

#[tokio::test]
async fn disabled_pruned_and_transport_errors_propagate_without_replay() {
    let mock = Mock::fault(-32601, "Method not found (disabled wallet)");
    let rpc = Provider::new(mock.clone());
    match rpc.wallet_info().await.unwrap_err() {
        Error::Rpc {
            method,
            code,
            message,
            status,
            data,
        } => {
            assert_eq!(method, "getwalletinfo");
            assert_eq!(code, -32601);
            assert_eq!(message, "Method not found (disabled wallet)");
            assert_eq!(status, 500);
            assert!(data.unwrap().get().contains("node"));
        }
        other => panic!("{other:?}"),
    }
    // Core 1.14.9 rescan's pruned-mode guard throws its help/runtime error (-1).
    let pruned = Mock::fault(-1, "rescan currently works only on non-pruned nodes");
    assert!(matches!(
        Provider::new(pruned.clone()).rescan(42).await,
        Err(Error::Rpc { code: -1, .. })
    ));
    assert_eq!(pruned.calls.lock().unwrap()[0].method, "rescan");
    assert_eq!(pruned.calls.lock().unwrap()[0].params, json!([42]));
    for multi in [false, true] {
        let timeout = Mock::timeout();
        let rpc = Provider::new(timeout.clone());
        let failed = if multi {
            rpc.import_multi(
                &[WatchImport::address("watch", ImportTimestamp::Now)],
                false,
            )
            .await
            .map(|_| ())
        } else {
            rpc.import_address("watch", None, false, false, None).await
        };
        assert!(matches!(
            failed,
            Err(Error::Transport(transport::Error::Timeout))
        ));
        assert_eq!(timeout.calls.lock().unwrap().len(), 1);
    }
}

#[tokio::test]
async fn dogecoin_rescan_result_is_typed_and_count_overrun_is_rejected() {
    let result = r#"{"before":{"balance":-1e-8,"txcount":2},"after":{"balance":1.00000001,"txcount":3},"blocks_scanned":7,"time_elapsed":0}"#;
    let mock = Mock::results(&[result, r#"[{"category":"move","amount":1}]"#]);
    let rpc = Provider::from_client(Client::new(mock.clone()));
    let result = rpc.rescan(42).await.unwrap();
    assert_eq!(result.before.balance.koinu(), -1);
    assert_eq!(result.after.balance.koinu(), 100_000_001);
    assert_eq!(result.blocks_scanned, 7);
    assert_eq!(result.time_elapsed.as_str(), "0");
    assert!(matches!(
        rpc.list_transactions("*", 0, 0, true).await,
        Err(Error::InvalidResponse { .. })
    ));
    assert_eq!(mock.calls.lock().unwrap().len(), 2);
}

/// Explicit isolated-node qualification. Requires the http feature and opt-in
/// URL/auth environment; checks regtest identity before any wallet mutation.
/// Imports public hash addresses only, does not generate keys, send or mine.
#[cfg(feature = "http")]
#[tokio::test]
#[ignore = "requires explicit isolated regtest URL/auth"]
async fn isolated_regtest_watch_import_read_and_rescan() {
    use planchet_primitives::{Address, Hash160, Network};
    use planchet_provider::transport::{BasicAuth, HttpConfig, HttpTransport};
    let endpoint = std::env::var("PLANCHET_WALLET_RPC_URL").expect("isolated regtest URL");
    let user = std::env::var("PLANCHET_WALLET_RPC_USER").expect("regtest user");
    let password = std::env::var("PLANCHET_WALLET_RPC_PASSWORD").expect("regtest password");
    let config = HttpConfig {
        max_response_bytes: MAX_LISTUNSPENT_RESPONSE_BYTES,
        ..HttpConfig::default()
    };
    let rpc = Provider::new(
        HttpTransport::new(&endpoint, Some(BasicAuth::new(user, password)), config).unwrap(),
    );
    rpc.validate_network(Network::Regtest).await.unwrap();
    let address =
        Address::p2pkh(Network::Regtest, Hash160::from_wire_bytes([0x37; 20])).to_string();
    let second = Address::p2pkh(Network::Regtest, Hash160::from_wire_bytes([0x38; 20])).to_string();
    assert!(rpc.validate_address(&address).await.unwrap().isvalid);
    rpc.import_address(&address, Some("planchet-watch-rpc"), false, false, Some(0))
        .await
        .unwrap();
    let mut request = WatchImport::address(&second, ImportTimestamp::Now);
    request.label = Some("planchet-watch-rpc".into());
    let results = rpc.import_multi(&[request], false).await.unwrap();
    assert!(results[0].success, "{results:?}");
    let watched = rpc.validate_address(&address).await.unwrap();
    assert_eq!(watched.iswatchonly, Some(true));
    assert_eq!(watched.ismine, Some(false));
    let received = rpc.list_received_by_address(0, true, true).await.unwrap();
    assert!(received.iter().any(|entry| entry.address == address));
    let snapshot = rpc
        .list_unspent(
            0,
            LIST_UNSPENT_MAXCONF,
            &[address, second],
            SnapshotLimits::default(),
        )
        .await
        .unwrap();
    assert!(snapshot.outputs.is_empty());
    let best = rpc.best_block_hash().await.unwrap();
    rpc.list_since_block(Some(best), 1, true).await.unwrap();
    rpc.list_transactions("*", 10, 0, true).await.unwrap();
    let info = rpc.wallet_info().await.unwrap();
    assert_eq!(info.walletversion, 130000);
    assert!(info.scanning.is_none());
    let height = rpc.block_count().await.unwrap();
    let rescan = rpc.rescan(height).await.unwrap();
    // Independent Core 1.14.9 contract: rpcwallet.cpp's rescan returns
    // chainActive.Height() - nHeight, so the current tip reports zero.
    // https://github.com/dogecoin/dogecoin/blob/v1.14.9/src/wallet/rpcwallet.cpp#L817
    assert_eq!(rescan.blocks_scanned, 0);
    assert_eq!(rescan.before.txcount, rescan.after.txcount);
}
