//! Independent expectations and provenance are described in VECTORS.md.
use planchet_primitives::{
    Address, AddressError, AddressKind, Amount, BlockHash, FeeRate, Hash160, MerkleRoot, Network,
    OutPoint, ParseAmountError, Sighash, Txid, Wtxid, hash160, sha256d,
};

fn hex<const N: usize>(text: &str) -> [u8; N] {
    assert_eq!(text.len(), N * 2);
    core::array::from_fn(|i| u8::from_str_radix(&text[2 * i..2 * i + 2], 16).unwrap())
}

#[test]
fn ids_reverse_text_exactly_once_and_signing_digests_never_reverse() {
    let wire = hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    let reversed = "1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100";
    assert_eq!(Txid::from_wire_bytes(wire).to_string(), reversed);
    assert_eq!(Wtxid::from_wire_bytes(wire).to_string(), reversed);
    assert_eq!(Wtxid::from_rpc_hex(reversed).unwrap().to_wire_bytes(), wire);
    assert_eq!(
        reversed
            .to_uppercase()
            .parse::<Wtxid>()
            .unwrap()
            .to_wire_bytes(),
        wire
    );
    assert_eq!(BlockHash::from_wire_bytes(wire).to_string(), reversed);
    assert_eq!(MerkleRoot::from_wire_bytes(wire).to_string(), reversed);
    assert_eq!(reversed.parse::<Txid>().unwrap().to_wire_bytes(), wire);
    assert_eq!(reversed.parse::<BlockHash>().unwrap().to_wire_bytes(), wire);
    assert_eq!(
        reversed.parse::<MerkleRoot>().unwrap().to_wire_bytes(),
        wire
    );
    let digest = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    assert_eq!(Sighash::from_wire_bytes(wire).to_string(), digest);
    assert_eq!(digest.parse::<Sighash>().unwrap().to_wire_bytes(), wire);
    assert_eq!(
        reversed
            .to_uppercase()
            .parse::<Txid>()
            .unwrap()
            .to_wire_bytes(),
        wire
    );
    for malformed in [
        "",
        "00",
        "0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        "gg0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        "é0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
    ] {
        assert!(malformed.parse::<Txid>().is_err(), "{malformed}");
        assert!(Wtxid::from_rpc_hex(malformed).is_err(), "{malformed}");
    }
}

#[test]
fn hash_known_answers() {
    assert_eq!(
        sha256d(b""),
        hex("5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456")
    );
    assert_eq!(
        sha256d(b"abc"),
        hex("4f8b42c22dd3729b519ba6f68d2da7cc5b2d606d05daed5ad5128cc03e6c6358")
    );
    assert_eq!(
        hash160(b""),
        hex("b472a266d0bd89c13706a4132ccfb16f7c3b9fcb")
    );
    assert_eq!(
        hash160(b"abc"),
        hex("bb1be98c142444d7a56aa3981c3942a978e4dc33")
    );
}

#[test]
fn core_genesis_headers_and_network_metadata() {
    let fixtures = [
        (
            Network::Mainnet,
            "main",
            "1a91e3dace36e2be3bf030a65679fe821aa1d6ef92e7c9902eb318182c355691",
            "010000000000000000000000000000000000000000000000000000000000000000000000696ad20e2dd4365c7459b4a4a5af743d5e92c6da3229e6532cd605f6533f2a5b24a6a152f0ff0f1e67860100",
            (30, 22, 158),
            60,
        ),
        (
            Network::Testnet,
            "test",
            "bb0a78264637406b6360aad926284d544d7049f45189db5664f3c4d07350559e",
            "010000000000000000000000000000000000000000000000000000000000000000000000696ad20e2dd4365c7459b4a4a5af743d5e92c6da3229e6532cd605f6533f2a5bb9a7f052f0ff0f1ef7390f00",
            (113, 196, 241),
            60,
        ),
        (
            Network::Regtest,
            "regtest",
            "3d2160a3b5dc4a9d62e7e66a295f70313ac808440ef7400d6c0772171ce973a5",
            "010000000000000000000000000000000000000000000000000000000000000000000000696ad20e2dd4365c7459b4a4a5af743d5e92c6da3229e6532cd605f6533f2a5bdae5494dffff7f2002000000",
            (111, 196, 239),
            1,
        ),
    ];
    for (network, core_name, expected, header, prefixes, spacing) in fixtures {
        assert_eq!(network.genesis_hash().to_string(), expected);
        assert_eq!(
            BlockHash::from_wire_bytes(sha256d(&hex::<80>(header))).to_string(),
            expected
        );
        assert_eq!(network.core_name(), core_name);
        assert_eq!(core_name.parse::<Network>().unwrap(), network);
        let params = network.params();
        assert_eq!(
            (params.p2pkh_prefix, params.p2sh_prefix, params.wif_prefix),
            prefixes
        );
        assert_eq!(params.target_spacing_secs, spacing);
    }
    for invalid in ["bitcoin", "signet", "testnet4", "", " MAINNET"] {
        assert!(invalid.parse::<Network>().is_err());
    }
}

#[test]
fn core_base58check_vectors_and_explicit_network_validation() {
    for (text, payload, network, kind) in [
        (
            "DD4KSSuBJqcjuTcvUg1CgUKeurPUFeEZkE",
            "56d9b1d684d5abef32134ebc6883d75d3a53e9be",
            Network::Mainnet,
            AddressKind::P2pkh,
        ),
        (
            "A7HRQk3GFCW2QasvdZxXuYj8kkQK5QrYLs",
            "a2dd71f34fe73314d6e37c44035513f203aa400b",
            Network::Mainnet,
            AddressKind::P2sh,
        ),
        (
            "nhRsrUaxZou6sewjqaS37cJrMRJRgwVXdk",
            "9131c29384f000c0d651660eefaf1717c8ca1855",
            Network::Testnet,
            AddressKind::P2pkh,
        ),
        (
            "2MsvyG12kxxipe276Au4zKqvd2xdrBuHWb3",
            "078457e357c6c4d8736515d14482089dd2a1f9f8",
            Network::Testnet,
            AddressKind::P2sh,
        ),
        (
            "mfWxJ45yp2SFn7UciZyNpvDKrzbhyfKrY8",
            "0000000000000000000000000000000000000000",
            Network::Regtest,
            AddressKind::P2pkh,
        ),
    ] {
        let address = Address::parse(text, network).unwrap();
        let hash = Hash160::from_wire_bytes(hex(payload));
        assert_eq!(address.payload(), hash);
        assert_eq!(address.kind(), kind);
        assert_eq!(address.network(), network);
        let constructed = match kind {
            AddressKind::P2pkh => Address::p2pkh(network, hash),
            AddressKind::P2sh => Address::p2sh(network, hash),
        };
        assert_eq!(constructed.to_string(), text);
    }
    let shared = "2MsvyG12kxxipe276Au4zKqvd2xdrBuHWb3";
    assert_eq!(
        Address::parse(shared, Network::Regtest).unwrap().kind(),
        AddressKind::P2sh
    );
    assert!(matches!(
        Address::parse(shared, Network::Mainnet),
        Err(AddressError::WrongNetwork { .. })
    ));
    assert!(Address::parse("nhRsrUaxZou6sewjqaS37cJrMRJRgwVXdk", Network::Regtest).is_err());
    assert_eq!(
        Address::parse("DD4KSSuBJqcjuTcvUg1CgUKeurPUFeEZkF", Network::Mainnet),
        Err(AddressError::InvalidChecksum)
    );
    for invalid in [
        "",
        "0OIl",
        " DD4KSSuBJqcjuTcvUg1CgUKeurPUFeEZkE",
        "DD4KSSuBJqcjuTcvUg1CgUKeurPUFeEZkE ",
        "111111111111111111111111111111111111",
    ] {
        assert!(Address::parse(invalid, Network::Mainnet).is_err());
    }
}

#[test]
fn exact_amounts_match_legacy_rpc_decimal_semantics() {
    for (text, koinu) in [
        ("0", 0),
        ("1", 100_000_000),
        ("1.2", 120_000_000),
        ("1e-8", 1),
        ("0.00000001", 1),
        ("12e2", 120_000_000_000),
        ("2.50E+2", 25_000_000_000),
        ("1.000000000e1", 1_000_000_000),
        ("396108366.15665016", 39_610_836_615_665_016),
        ("176000592.43399879", 17_600_059_243_399_879),
        ("90071992.54740993", 9_007_199_254_740_993),
        ("184467440737.09551615", u64::MAX),
        ("0e30", 0),
        (".1", 10_000_000),
        ("1.", 100_000_000),
        (".", 0),
    ] {
        assert_eq!(
            Amount::from_doge_str(text).unwrap().to_koinu(),
            koinu,
            "{text}"
        );
    }
    for text in ["1e-9", "0.0000000100", "1.000000000", "0.000000000", "0e-9"] {
        assert_eq!(
            text.parse::<Amount>(),
            Err(ParseAmountError::TooPrecise),
            "{text}"
        );
    }
    for text in [
        "184467440737.09551616",
        "1e30",
        "0e31",
        "0e2147483647",
        "0e-2147483648",
    ] {
        assert_eq!(
            text.parse::<Amount>(),
            Err(ParseAmountError::Overflow),
            "{text}"
        );
    }
    for text in [
        "",
        "+1",
        "1 DOGE",
        " 1",
        "NaN",
        "1e",
        "1e1e1",
        "1.2.3",
        "0e999999999999999999999",
    ] {
        assert_eq!(
            text.parse::<Amount>(),
            Err(ParseAmountError::InvalidSyntax),
            "{text}"
        );
    }
    for text in ["-0", "-1", "-0.1"] {
        assert_eq!(text.parse::<Amount>(), Err(ParseAmountError::Negative));
    }
    assert_eq!(Amount::from_koinu(1).to_string(), "0.00000001");
    assert_eq!(Amount::MAX.to_string(), "184467440737.09551615");
}

#[test]
fn amount_arithmetic_and_fee_rounding_are_checked() {
    assert_eq!(
        Amount::ONE_DOGE.checked_add(Amount::from_koinu(1)),
        Some(Amount::from_koinu(100_000_001))
    );
    assert_eq!(Amount::MAX.checked_add(Amount::from_koinu(1)), None);
    assert_eq!(Amount::ZERO.checked_sub(Amount::from_koinu(1)), None);
    assert_eq!(Amount::MAX.checked_mul(2), None);
    assert_eq!(
        Amount::ONE_DOGE.checked_mul(2),
        Some(Amount::from_koinu(200_000_000))
    );
    assert_eq!(
        Amount::ONE_DOGE.checked_sub(Amount::from_koinu(1)),
        Some(Amount::from_koinu(99_999_999))
    );
    assert_eq!(
        Amount::ONE_DOGE.checked_div(2),
        Some(Amount::from_koinu(50_000_000))
    );
    assert_eq!(Amount::ONE_DOGE.checked_div(0), None);
    for (rate, bytes, expected) in [
        (1, 1, 1),
        (1, 1000, 1),
        (1, 1001, 2),
        (1234, 250, 309),
        (0, u64::MAX, 0),
        (u64::MAX, 0, 0),
        (u64::MAX, 1000, u64::MAX),
    ] {
        assert_eq!(
            FeeRate::from_koinu_per_kvb(rate).fee_for_vbytes(bytes),
            Some(Amount::from_koinu(expected))
        );
    }
    assert_eq!(
        FeeRate::from_koinu_per_kvb(u64::MAX).fee_for_bytes(1001),
        None
    );
    assert!(OutPoint::NULL.is_null());
    assert!(!OutPoint::new(Txid::ZERO, 0).is_null());
    assert!(!OutPoint::new(Txid::from_wire_bytes([1; 32]), u32::MAX).is_null());
}
