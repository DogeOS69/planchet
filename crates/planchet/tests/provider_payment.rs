//! The same real payment exercises fallback software and application providers.
#![cfg(all(feature = "psbt", feature = "signer"))]

use planchet::{
    consensus::{
        sighash::{SighashType, legacy_sighash},
        transaction::{PaymentBudget, Prevout, Transaction},
    },
    psbt::{Error as PsbtError, PsbtV0},
    signer::{EcdsaSignature, Error as SignerError, PublicKey, verify_historical, verify_prehash},
};

#[cfg(feature = "crypto-backend")]
mod provider {
    use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use planchet::crypto::{CryptoProvider, SoftwareCrypto, VerifyError};

    pub static VERIFICATIONS: AtomicUsize = AtomicUsize::new(0);
    pub static REJECT: AtomicBool = AtomicBool::new(false);
    pub static LAST_KEY: std::sync::Mutex<Vec<u8>> = std::sync::Mutex::new(Vec::new());
    pub static CRYPTO: PaymentCrypto = PaymentCrypto;

    pub struct PaymentCrypto;
    impl CryptoProvider for PaymentCrypto {
        // Hashing and SEC1 validation deliberately retain default software methods.
        fn verify_k256_prehash(
            &self,
            key: &[u8],
            digest: &[u8; 32],
            signature: &[u8; 64],
        ) -> Result<(), VerifyError> {
            VERIFICATIONS.fetch_add(1, Ordering::Relaxed);
            *LAST_KEY.lock().unwrap() = key.to_vec();
            if REJECT.load(Ordering::Relaxed) {
                return Err(VerifyError::InvalidSignature);
            }
            SoftwareCrypto.verify_k256_prehash(key, digest, signature)
        }
    }
}

fn hex(text: &str) -> Vec<u8> {
    text.as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(core::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

#[test]
fn ordinary_signer_and_psbt_preserve_payment_and_software_policy() {
    let signed_bytes = include_bytes!("data/payment-signed.bin");
    let signed = Transaction::decode_exact(signed_bytes, Default::default()).unwrap();
    let parent = Transaction::decode_exact(
        include_bytes!("data/payment-parent.bin"),
        Default::default(),
    )
    .unwrap();
    let prevout = Prevout::from_parent(signed.inputs[0].previous_output, &parent).unwrap();
    let mut unsigned = signed.clone();
    let script = core::mem::take(&mut unsigned.inputs[0].script_sig);
    let siglen = usize::from(script[0]);
    assert_eq!(script[siglen], 1); // SIGHASH_ALL follows strict DER.
    assert_eq!(script[siglen + 1], 33); // Compressed SEC1 push.
    let der = &script[1..siglen];
    // Construct before installation to protect late provider dispatch.
    let key = PublicKey::from_sec1_bytes(&script[siglen + 2..]).unwrap();
    assert_eq!(key.as_bytes(), &script[siglen + 2..]);
    // SEC1 generator coordinates: the same curve point has distinct wire keys.
    let uncompressed_bytes = hex(
        "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8",
    );
    let uncompressed = PublicKey::from_sec1_bytes(&uncompressed_bytes).unwrap();
    assert_ne!(key, uncompressed);
    assert_eq!(uncompressed.as_bytes(), uncompressed_bytes);
    let signature = EcdsaSignature::from_low_s_der(der).unwrap();
    let digest = legacy_sighash(&unsigned, 0, &prevout.output.script_pubkey, 1);
    verify_prehash(&key, digest, &signature).unwrap();

    #[cfg(feature = "crypto-backend")]
    assert!(planchet::crypto::install_default_provider(&provider::CRYPTO).is_ok());

    verify_prehash(&key, digest, &signature).unwrap();
    #[cfg(feature = "crypto-backend")]
    assert!(provider::VERIFICATIONS.load(core::sync::atomic::Ordering::Relaxed) > 0);
    verify_prehash(&uncompressed, digest, &signature).unwrap();
    #[cfg(feature = "crypto-backend")]
    assert_eq!(*provider::LAST_KEY.lock().unwrap(), uncompressed_bytes);

    // Independent n - s of the Core signature (see fixture provenance).
    let high_der = hex(
        "30460221008d00a7f6919c76ccdd0f900295204ea4ba6e71b004b671f721162632a99e3ff50221008af7411766779cf1868b096a95a8611b998fb4a3dbb1b02b47bda0187a833833",
    );
    let high = EcdsaSignature::from_der(&high_der).unwrap();
    verify_historical(&key, digest, &high).unwrap();
    assert_eq!(high.as_der(), high_der);
    #[cfg(feature = "crypto-backend")]
    let before_policy = provider::VERIFICATIONS.load(core::sync::atomic::Ordering::Relaxed);
    assert_eq!(verify_prehash(&key, digest, &high), Err(SignerError::HighS));
    assert_eq!(
        EcdsaSignature::from_low_s_der(&high_der),
        Err(SignerError::HighS)
    );
    assert_eq!(
        EcdsaSignature::from_der(&[0x30, 0]),
        Err(SignerError::InvalidDer)
    );
    assert_eq!(
        PublicKey::from_sec1_bytes(&[2; 32]),
        Err(SignerError::InvalidPublicKey)
    );
    #[cfg(feature = "crypto-backend")]
    assert_eq!(
        provider::VERIFICATIONS.load(core::sync::atomic::Ordering::Relaxed),
        before_policy
    );

    let budget = PaymentBudget {
        max_fee: 1_000_000,
        min_fee_rate_koinu_per_kvb: 1000,
    };
    let prevouts = [prevout];
    let mut psbt = PsbtV0::from_unsigned(unsigned).unwrap();
    psbt.attach_parent(0, &parent).unwrap();
    let request = psbt
        .sign_request(0, &prevouts, key.as_bytes(), SighashType::All, budget)
        .unwrap();
    assert_eq!(request.digest(), digest);
    let original = psbt.encode();
    assert_eq!(
        psbt.insert_verified_signature(&request, key.as_bytes(), &high_der, SighashType::All),
        Err(PsbtError::HighS)
    );
    assert_eq!(psbt.encode(), original);
    assert_eq!(
        psbt.insert_verified_signature(&request, key.as_bytes(), &[0x30, 0], SighashType::All),
        Err(PsbtError::InvalidSignature)
    );
    assert_eq!(psbt.encode(), original);

    #[cfg(feature = "crypto-backend")]
    {
        use core::sync::atomic::Ordering;
        provider::REJECT.store(true, Ordering::Relaxed);
        assert_eq!(
            verify_prehash(&key, digest, &signature),
            Err(SignerError::InvalidSignature)
        );
        assert_eq!(
            psbt.insert_verified_signature(&request, key.as_bytes(), der, SighashType::All),
            Err(PsbtError::InvalidSignature)
        );
        assert_eq!(psbt.encode(), original);
        #[cfg(feature = "signer-local")]
        {
            let mut secret = [0; 32];
            secret[31] = 1; // Public scalar-one generator fixture.
            let local_key = planchet::signer::LocalSigner::from_bytes(&secret)
                .unwrap()
                .with_compressed_public_key(false)
                .public_key();
            assert_eq!(local_key, uncompressed);
            assert_eq!(
                verify_prehash(&local_key, digest, &signature),
                Err(SignerError::InvalidSignature)
            );
            assert_eq!(*provider::LAST_KEY.lock().unwrap(), uncompressed_bytes);
        }
        provider::REJECT.store(false, Ordering::Relaxed);
    }

    psbt.insert_verified_signature(&request, key.as_bytes(), der, SighashType::All)
        .unwrap();
    let payment = psbt.finalize_p2pkh(&prevouts, budget).unwrap();
    assert_eq!(payment.encode(), signed_bytes.as_slice());
    assert_eq!(payment.summary().fee, 1_000_000);
    assert_eq!(
        payment.transaction().txid().to_string(),
        "3cd139ff08015a742456f341bd5a6105954bef85c69ad3e581c429454b8e844a"
    );
    assert_eq!(psbt.extract(&prevouts, budget).unwrap(), payment);
}
