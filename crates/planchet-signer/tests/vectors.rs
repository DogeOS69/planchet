#![cfg(feature = "verify")]
use planchet_primitives::Sighash;
use planchet_signer::{EcdsaSignature, Error, PublicKey, verify_historical, verify_prehash};

fn hex(text: &str) -> Vec<u8> {
    text.as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(core::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

// Independent C2SP/Wycheproof secp256k1/SHA256 vectors. The digest literals are
// SHA256(message), precomputed outside this implementation. This protects the
// prehash boundary, DER strictness, curve/scalar validation and high-S policy.
#[test]
fn wycheproof_prehash_and_strict_der() {
    let data: serde_json::Value =
        serde_json::from_str(include_str!("data/wycheproof.json")).unwrap();
    for case in data["tests"].as_array().unwrap() {
        let public_key = PublicKey::from_sec1_bytes(&hex(case["key"].as_str().unwrap())).unwrap();
        let digest =
            Sighash::from_wire_bytes(hex(case["digest"].as_str().unwrap()).try_into().unwrap());
        let signature = EcdsaSignature::from_der(&hex(case["der"].as_str().unwrap()));
        let result = signature
            .as_ref()
            .map_err(|_| Error::InvalidDer)
            .and_then(|sig| verify_historical(&public_key, digest, sig));
        match case["result"].as_str().unwrap() {
            "valid" => {
                assert!(
                    result.is_ok(),
                    "tcId {} {}: {result:?}",
                    case["tcId"],
                    case["comment"]
                );
                let signature = signature.unwrap();
                assert_eq!(
                    verify_prehash(&public_key, digest, &signature).is_ok(),
                    signature.is_low_s()
                );
                // Mathematical verification never rewrites original DER.
                assert_eq!(signature.as_der(), hex(case["der"].as_str().unwrap()));
            }
            "invalid" => assert!(result.is_err(), "tcId {} {}", case["tcId"], case["comment"]),
            "acceptable" => {
                // Wycheproof's acceptable legacy encodings are deliberately
                // outside our documented strict-DER policy.
                if signature.is_ok() {
                    assert!(result.is_ok(), "tcId {}", case["tcId"]);
                }
            }
            other => panic!("unexpected vector classification {other}"),
        }
    }
}

#[test]
fn rejects_malformed_off_curve_and_hybrid_keys() {
    for key in [
        vec![],
        vec![2; 32],
        vec![4; 33],
        vec![6; 65],
        vec![7; 65],
        vec![0; 65],
    ] {
        assert!(PublicKey::from_sec1_bytes(&key).is_err());
    }
    let mut out_of_field = vec![0xff; 33];
    out_of_field[0] = 2;
    assert!(PublicKey::from_sec1_bytes(&out_of_field).is_err());
}
