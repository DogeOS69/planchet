use hex_literal::hex;
use planchet_crypto::{CryptoProvider, SoftwareCrypto, crypto_provider};

#[test]
fn object_safe_software_defaults_hash_once_and_stream_parts() {
    struct Defaults;
    impl CryptoProvider for Defaults {}
    let provider: &dyn CryptoProvider = &Defaults;
    let abc = hex!("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    assert_eq!(provider.sha256(b"abc"), abc);
    assert_eq!(provider.sha256_parts(&[b"a", b"", b"bc"]), abc);
    assert_eq!(
        provider.sha256_parts(&[]),
        hex!("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
    );
    assert_eq!(SoftwareCrypto.sha256(b"abc"), abc);
    #[cfg(not(feature = "crypto-backend"))]
    assert_eq!(crypto_provider().sha256(b"abc"), abc);
    #[cfg(feature = "keccak")]
    assert_eq!(
        provider.keccak256(b"abc"),
        hex!("4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45")
    );
}

// This integration-test binary owns its registry. No other test installs here.
#[cfg(feature = "crypto-backend")]
#[test]
fn reading_does_not_register_and_exactly_one_concurrent_install_succeeds() {
    use planchet_crypto::install_default_provider;
    #[cfg(any(feature = "k256", feature = "p256"))]
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Barrier};
    #[cfg(feature = "k256")]
    static K_VALIDATE: AtomicUsize = AtomicUsize::new(0);
    #[cfg(feature = "k256")]
    static K_VERIFY: AtomicUsize = AtomicUsize::new(0);
    #[cfg(feature = "p256")]
    static P_VALIDATE: AtomicUsize = AtomicUsize::new(0);
    #[cfg(feature = "p256")]
    static P_VERIFY: AtomicUsize = AtomicUsize::new(0);

    struct Override;
    impl CryptoProvider for Override {
        fn sha256(&self, _: &[u8]) -> [u8; 32] {
            [42; 32]
        }
        #[cfg(feature = "k256")]
        fn validate_k256_public_key(&self, key: &[u8]) -> Result<(), planchet_crypto::VerifyError> {
            K_VALIDATE.fetch_add(1, Ordering::Relaxed);
            SoftwareCrypto.validate_k256_public_key(key)
        }
        #[cfg(feature = "k256")]
        fn verify_k256_prehash(
            &self,
            key: &[u8],
            digest: &[u8; 32],
            sig: &[u8; 64],
        ) -> Result<(), planchet_crypto::VerifyError> {
            K_VERIFY.fetch_add(1, Ordering::Relaxed);
            SoftwareCrypto.verify_k256_prehash(key, digest, sig)
        }
        #[cfg(feature = "p256")]
        fn validate_p256_public_key(&self, key: &[u8]) -> Result<(), planchet_crypto::VerifyError> {
            P_VALIDATE.fetch_add(1, Ordering::Relaxed);
            SoftwareCrypto.validate_p256_public_key(key)
        }
        #[cfg(feature = "p256")]
        fn verify_p256_prehash(
            &self,
            key: &[u8],
            digest: &[u8; 32],
            sig: &[u8; 64],
        ) -> Result<(), planchet_crypto::VerifyError> {
            P_VERIFY.fetch_add(1, Ordering::Relaxed);
            SoftwareCrypto.verify_p256_prehash(key, digest, sig)
        }
    }
    static PROVIDER: Override = Override;
    static OTHER: SoftwareCrypto = SoftwareCrypto;

    // Cached keys created with software must use the provider installed later.
    #[cfg(feature = "k256")]
    let k_key = {
        let uncompressed = hex!(
            "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"
        );
        let compressed = hex!("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798");
        let key = planchet_crypto::K256VerifyingKey::from_sec1_bytes(&uncompressed).unwrap();
        assert_eq!(
            key,
            planchet_crypto::K256VerifyingKey::from_sec1_bytes(&compressed).unwrap()
        );
        key
    };
    #[cfg(feature = "p256")]
    let p_key = {
        let uncompressed = hex!(
            "046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"
        );
        let compressed = hex!("036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296");
        let key = planchet_crypto::P256VerifyingKey::from_sec1_bytes(&uncompressed).unwrap();
        assert_eq!(
            key,
            planchet_crypto::P256VerifyingKey::from_sec1_bytes(&compressed).unwrap()
        );
        key
    };
    // Ordinary use must not reserve the install slot for the software default.
    assert_eq!(
        crypto_provider().sha256(b"abc"),
        SoftwareCrypto.sha256(b"abc")
    );
    let barrier = Arc::new(Barrier::new(16));
    let handles: Vec<_> = (0..16)
        .map(|_| {
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                install_default_provider(&PROVIDER).is_ok()
            })
        })
        .collect();
    assert_eq!(
        handles
            .into_iter()
            .map(|h| usize::from(h.join().unwrap()))
            .sum::<usize>(),
        1
    );
    assert_eq!(crypto_provider().sha256(b"abc"), [42; 32]);
    #[cfg(feature = "k256")]
    {
        assert_eq!(
            k_key.verify_prehash(&[0; 32], &[0; 64]),
            Err(planchet_crypto::VerifyError::InvalidSignature)
        );
        assert_eq!(K_VERIFY.load(Ordering::Relaxed), 1);
        assert_eq!(K_VALIDATE.load(Ordering::Relaxed), 0);
        let compressed = hex!("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798");
        assert_eq!(
            planchet_crypto::validate_k256_public_key(&compressed),
            Ok(())
        );
        assert_eq!(K_VALIDATE.load(Ordering::Relaxed), 1);
        assert_eq!(
            planchet_crypto::validate_k256_public_key(&[0; 33]),
            Err(planchet_crypto::VerifyError::InvalidPublicKey)
        );
        assert_eq!(
            planchet_crypto::verify_k256_prehash(&[0; 33], &[0; 32], &[0; 64]),
            Err(planchet_crypto::VerifyError::InvalidPublicKey)
        );
        assert_eq!(K_VALIDATE.load(Ordering::Relaxed), 1);
        assert_eq!(K_VERIFY.load(Ordering::Relaxed), 1);
    }
    #[cfg(feature = "p256")]
    {
        assert_eq!(
            p_key.verify_prehash(&[0; 32], &[0; 64]),
            Err(planchet_crypto::VerifyError::InvalidSignature)
        );
        assert_eq!(P_VERIFY.load(Ordering::Relaxed), 1);
        assert_eq!(P_VALIDATE.load(Ordering::Relaxed), 0);
        let compressed = hex!("036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296");
        assert_eq!(
            planchet_crypto::validate_p256_public_key(&compressed),
            Ok(())
        );
        assert_eq!(P_VALIDATE.load(Ordering::Relaxed), 1);
        assert_eq!(
            planchet_crypto::validate_p256_public_key(&[0; 33]),
            Err(planchet_crypto::VerifyError::InvalidPublicKey)
        );
        assert_eq!(
            planchet_crypto::verify_p256_prehash(&[0; 33], &[0; 32], &[0; 64]),
            Err(planchet_crypto::VerifyError::InvalidPublicKey)
        );
        assert_eq!(P_VALIDATE.load(Ordering::Relaxed), 1);
        assert_eq!(P_VERIFY.load(Ordering::Relaxed), 1);
    }
    // Even reinstalling the same pointer must report failure.
    assert!(install_default_provider(&PROVIDER).is_err());
    assert!(install_default_provider(&OTHER).is_err());
    assert_eq!(crypto_provider().sha256(b"abc"), [42; 32]);
    // An omitted override uses software directly, without recursing via sha256.
    assert_eq!(
        crypto_provider().sha256_parts(&[b"a", b"bc"]),
        SoftwareCrypto.sha256(b"abc")
    );
}
