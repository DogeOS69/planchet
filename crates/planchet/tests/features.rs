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
