#![cfg(feature = "alloc")]
use planchet_consensus::{DecodeLimits, sighash::legacy_sighash, transaction::Transaction};
use planchet_psbt::{PsbtLimits, PsbtV0};

fn hex(text: &str) -> Vec<u8> {
    text.as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(core::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

// Contract: the published BIP174 accept/reject classification and original
// bytes. Catches map arity, duplicate keys, typed-key and unsigned-tx mistakes.
#[test]
fn official_bip174_codec_vectors() {
    let cases: serde_json::Value = serde_json::from_str(include_str!("data/bip174.json")).unwrap();
    for case in cases.as_array().unwrap() {
        let bytes = hex(case["hex"].as_str().unwrap());
        let result = PsbtV0::decode(&bytes, PsbtLimits::default());
        if case["valid"].as_bool().unwrap() {
            let psbt = result.unwrap_or_else(|e| panic!("{}: {e}", case["case"]));
            assert_eq!(psbt.encode(), bytes, "{}", case["case"]);
        } else {
            assert!(result.is_err(), "{}", case["case"]);
        }
    }
}

// Source: Dogecoin Core v1.14.9 src/test/data/sighash.json (MIT).
// Expected hashes are copied from Core, in its displayed uint256 byte order.
// Nontrivial scriptCode exercises CODESEPARATOR and arbitrary hash-type bits.
#[test]
fn independent_core_sighash_vectors() {
    let cases: serde_json::Value =
        serde_json::from_str(include_str!("data/core-sighash.json")).unwrap();
    for row in &cases.as_array().unwrap()[1..] {
        let bytes = hex(row[0].as_str().unwrap());
        let tx = Transaction::decode_exact(&bytes, DecodeLimits::default()).unwrap();
        assert_eq!(tx.encode(), bytes);
        let script = hex(row[1].as_str().unwrap());
        let hash_type = row[3].as_i64().unwrap() as i32 as u32;
        let digest = legacy_sighash(&tx, row[2].as_u64().unwrap() as usize, &script, hash_type);
        let mut expected = hex(row[4].as_str().unwrap());
        expected.reverse();
        assert_eq!(
            digest.as_ref(),
            expected,
            "hash type {hash_type:#x}, script {script:x?}"
        );
    }
}
