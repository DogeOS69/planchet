//! Compile/use the real feature-gated API, so an empty crate reexport cannot pass.

#[cfg(feature = "psbt")]
#[test]
fn psbt_feature_exposes_owned_psbt_api() {
    use planchet::psbt::{Error, PsbtLimits, PsbtV0};
    // BIP174 requires the literal psbt\xff magic before any map.
    assert!(matches!(
        PsbtV0::decode(b"not-psbt", PsbtLimits::default()),
        Err(Error::Magic)
    ));
}

#[cfg(feature = "signer-local")]
#[test]
fn local_feature_exposes_signer_contract_and_constructor() {
    use planchet::signer::{DigestSigner, Error, LocalSigner};
    fn implements_signer<T: DigestSigner>() {}
    implements_signer::<LocalSigner>();
    let _: fn(&[u8; 32]) -> Result<LocalSigner, Error> = LocalSigner::from_bytes;
}

#[cfg(all(feature = "psbt", feature = "signer-local"))]
#[test]
fn combined_features_expose_psbt_signer_adapter() {
    use planchet::{
        psbt::P2pkhSignRequest,
        signer::{Error, SignRequest},
    };
    let _: fn(&P2pkhSignRequest) -> Result<SignRequest, Error> = SignRequest::from_psbt;
}

#[test]
fn sha256_is_available_without_optional_backends() {
    // FIPS 180-4 / NIST SHA-256 empty-message digest, in raw byte order.
    assert_eq!(
        planchet::sha256(b""),
        [
            0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f,
            0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b,
            0x78, 0x52, 0xb8, 0x55,
        ]
    );
}

#[cfg(feature = "keccak")]
#[test]
fn keccak_feature_exposes_ethereum_padding() {
    // Keccak-256's empty-message digest differs from SHA3-256's a7ffc6f8….
    assert_eq!(
        planchet::keccak256(b""),
        [
            0xc5, 0xd2, 0x46, 0x01, 0x86, 0xf7, 0x23, 0x3c, 0x92, 0x7e, 0x7d, 0xb2, 0xdc, 0xc7,
            0x03, 0xc0, 0xe5, 0x00, 0xb6, 0x53, 0xca, 0x82, 0x27, 0x3b, 0x7b, 0xfa, 0xd8, 0x04,
            0x5d, 0x85, 0xa4, 0x70,
        ]
    );
}

#[cfg(feature = "k256")]
#[test]
fn k256_feature_exposes_checked_prehash_verification() {
    assert_eq!(
        planchet::crypto::verify_k256_prehash(&[], &[0; 32], &[0; 64]),
        Err(planchet::crypto::VerifyError::InvalidPublicKey)
    );
}

#[cfg(feature = "p256")]
#[test]
fn p256_feature_exposes_checked_prehash_verification() {
    assert_eq!(
        planchet::crypto::verify_p256_prehash(&[], &[0; 32], &[0; 64]),
        Err(planchet::crypto::VerifyError::InvalidPublicKey)
    );
}

#[cfg(feature = "signer")]
#[test]
fn signer_feature_exposes_verification_contract() {
    // SEC1 has no empty-key encoding. Verification-only consumers need this API
    // without enabling LocalSigner or private-key handling.
    assert!(planchet::signer::PublicKey::from_sec1_bytes(&[]).is_err());
}
