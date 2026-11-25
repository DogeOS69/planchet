#![cfg(any(feature = "k256", feature = "p256"))]

use hex_literal::hex;
use planchet_crypto::VerifyError;

type Verify = fn(&[u8], &[u8; 32], &[u8; 64]) -> Result<(), VerifyError>;

// Independent d = k = 1 ECDSA fixtures: Q = G, r = G.x, s = (z + r) mod n.
// Prehash = Python hashlib.sha256(b"abc"). No signing implementation under
// test supplies the expectations. These catch rehashing, high-S policy leakage,
// key-validation shortcuts, missing scalar range checks, and identity results.
const PREHASH: [u8; 32] = hex!("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");

struct Vector {
    verify: Verify,
    verify_cached: Verify,
    key: [u8; 65],
    signature: [u8; 64],
    high_s: [u8; 32],
    order: [u8; 32],
    order_minus_one: [u8; 32],
    modulus: [u8; 32],
    max_digest_s: [u8; 32],
    nonresidue_x: [u8; 32],
}

fn exercise(v: Vector) {
    for verify in [v.verify, v.verify_cached] {
        exercise_with(&v, verify);
    }
}

fn exercise_with(v: &Vector, verify: Verify) {
    let mut compressed = [0; 33];
    compressed[0] = 2 | (v.key[64] & 1);
    compressed[1..].copy_from_slice(&v.key[1..33]);
    for key in [&v.key[..], &compressed[..]] {
        assert_eq!(verify(key, &PREHASH, &v.signature), Ok(()));
        let mut high = v.signature;
        high[32..].copy_from_slice(&v.high_s);
        assert_eq!(verify(key, &PREHASH, &high), Ok(()));
        assert_eq!(
            verify(key, &[0; 32], &v.signature),
            Err(VerifyError::InvalidSignature)
        );

        // A prehash is an arbitrary 256-bit integer, not a canonical scalar.
        let mut reduced = v.signature;
        reduced[32..].copy_from_slice(&v.key[1..33]);
        assert_eq!(verify(key, &[0; 32], &reduced), Ok(()));
        assert_eq!(verify(key, &v.order, &reduced), Ok(()));
        reduced[32..].copy_from_slice(&v.max_digest_s);
        assert_eq!(verify(key, &[0xff; 32], &reduced), Ok(()));

        for offset in [0, 32] {
            for scalar in [[0; 32], v.order, [0xff; 32]] {
                let mut invalid = v.signature;
                invalid[offset..offset + 32].copy_from_slice(&scalar);
                assert_eq!(
                    verify(key, &PREHASH, &invalid),
                    Err(VerifyError::InvalidSignature)
                );
            }
        }

        // With Q = G, z = n-1 and r = s = 1, R = -G + G = identity.
        let mut identity_result = [0; 64];
        identity_result[31] = 1;
        identity_result[63] = 1;
        assert_eq!(
            verify(key, &v.order_minus_one, &identity_result),
            Err(VerifyError::InvalidSignature)
        );
    }

    compressed[0] ^= 1; // -G is on-curve, but cannot verify G's signature.
    assert_eq!(
        verify(&compressed, &PREHASH, &v.signature),
        Err(VerifyError::InvalidSignature)
    );

    for key in [
        vec![],
        vec![0],
        vec![2; 32],
        vec![4; 33],
        vec![6; 65],
        vec![7; 65],
    ] {
        assert_eq!(
            verify(&key, &PREHASH, &v.signature),
            Err(VerifyError::InvalidPublicKey)
        );
    }

    let mut invalid = v.key;
    invalid[1..].fill(0); // (0,0) is not a valid SEC1 curve point.
    assert_eq!(
        verify(&invalid, &PREHASH, &v.signature),
        Err(VerifyError::InvalidPublicKey)
    );
    invalid[64] = 1; // Canonical coordinates, off the curve.
    assert_eq!(
        verify(&invalid, &PREHASH, &v.signature),
        Err(VerifyError::InvalidPublicKey)
    );
    for offset in [1, 33] {
        for coordinate in [v.modulus, [0xff; 32]] {
            invalid = v.key;
            invalid[offset..offset + 32].copy_from_slice(&coordinate);
            assert_eq!(
                verify(&invalid, &PREHASH, &v.signature),
                Err(VerifyError::InvalidPublicKey)
            );
        }
    }
    for x in [v.modulus, [0xff; 32], v.nonresidue_x] {
        for prefix in [2, 3] {
            compressed[0] = prefix;
            compressed[1..].copy_from_slice(&x);
            assert_eq!(
                verify(&compressed, &PREHASH, &v.signature),
                Err(VerifyError::InvalidPublicKey)
            );
        }
    }
}

#[cfg(feature = "k256")]
#[test]
fn k256_compact_contract() {
    exercise(Vector {
        verify: planchet_crypto::verify_k256_prehash,
        verify_cached: |key, digest, signature| {
            planchet_crypto::K256VerifyingKey::from_sec1_bytes(key)?
                .verify_prehash(digest, signature)
        },
        key: hex!(
            "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"
        ),
        signature: hex!(
            "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f8179834367d3e88de8b9696e1a3742c352d2bf7f08198149d033a4e31223038c1ec04"
        ),
        high_s: hex!("cbc982c177217469691e5c8bd3cad2d2c2be5b4e9aab9d0171a13c5c9774553d"),
        order: hex!("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"),
        order_minus_one: hex!("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140"),
        modulus: hex!("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f"),
        max_digest_s: hex!("79be667ef9dcbbac55a06295ce870b0847ed1ff47e85889d9a2022ce46c1d656"),
        // x=0 gives x^3+7=7, a nonsquare in the secp256k1 base field.
        nonresidue_x: [0; 32],
    });
}

#[cfg(feature = "p256")]
#[test]
fn p256_compact_contract() {
    exercise(Vector {
        verify: planchet_crypto::verify_p256_prehash,
        verify_cached: |key, digest, signature| {
            planchet_crypto::P256VerifyingKey::from_sec1_bytes(key)?
                .verify_prehash(digest, signature)
        },
        key: hex!(
            "046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"
        ),
        signature: hex!(
            "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296258fe8b3702e123139fe27c3c15263166a1fe4771ceb0fb8b4f86de4ce35b2f2"
        ),
        high_s: hex!("da70174b8fd1edcfc601d83c3ead9ce952c716368a2c8ecc3ec15cde2e2d725f"),
        order: hex!("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551"),
        order_minus_one: hex!("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550"),
        modulus: hex!("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff"),
        max_digest_s: hex!("6b17d1f3e12c4246f8bce6e563a440f2ba1c82d386d3951c00e76e82dc359d44"),
        // x=1 gives 1-3+b, a nonsquare in the P-256 base field.
        nonresidue_x: hex!("0000000000000000000000000000000000000000000000000000000000000001"),
    });
}

#[cfg(feature = "p256")]
#[test]
fn rfc6979_p256_sha256_sample_high_s() {
    // RFC 6979 A.2.5, SHA-256("sample"); high S must remain accepted.
    // https://www.rfc-editor.org/rfc/rfc6979#appendix-A.2.5
    let key = hex!(
        "0460fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb67903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299"
    );
    let prehash = hex!("af2bdbe1aa9b6ec1e2ade1d694f41fc71a831d0268e9891562113d8a62add1bf");
    let signature = hex!(
        "efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8"
    );
    assert_eq!(
        planchet_crypto::verify_p256_prehash(&key, &prehash, &signature),
        Ok(())
    );
}

#[cfg(feature = "k256")]
#[test]
fn wycheproof_compact_verification() {
    // Reuse the independently frozen corpus; DER is decoded only to translate
    // existing fixtures to this API. DER acceptance remains the caller's job.
    let data: serde_json::Value = serde_json::from_str(include_str!(
        "../../planchet-signer/tests/data/wycheproof.json"
    ))
    .unwrap();
    let decode = |s: &str| -> Vec<u8> {
        s.as_bytes()
            .chunks_exact(2)
            .map(|pair| u8::from_str_radix(core::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect()
    };
    for case in data["tests"].as_array().unwrap() {
        let Ok(signature) =
            k256::ecdsa::Signature::from_der(&decode(case["der"].as_str().unwrap()))
        else {
            continue;
        };
        let key = decode(case["key"].as_str().unwrap());
        let digest = decode(case["digest"].as_str().unwrap()).try_into().unwrap();
        let result =
            planchet_crypto::verify_k256_prehash(&key, &digest, &signature.to_bytes().into());
        assert_eq!(
            result.is_ok(),
            case["result"] != "invalid",
            "tcId {}: {result:?}",
            case["tcId"]
        );
    }
}
