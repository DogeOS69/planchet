//! An external SHA-only consumer: registration must need no optional algorithms.
#![cfg(feature = "crypto-backend")]

use core::sync::atomic::{AtomicUsize, Ordering};
use planchet::{
    TxRef,
    crypto::{CryptoProvider, SoftwareCrypto, crypto_provider, install_default_provider},
};

static HASHES: AtomicUsize = AtomicUsize::new(0);
static PROVIDER: CountingSha = CountingSha;

struct CountingSha;
impl CryptoProvider for CountingSha {
    fn sha256(&self, input: &[u8]) -> [u8; 32] {
        HASHES.fetch_add(1, Ordering::Relaxed);
        SoftwareCrypto.sha256(input)
    }
}

#[test]
fn ordinary_transaction_hash_uses_a_late_installed_sha_only_provider() {
    let tx = TxRef::decode_exact(
        include_bytes!("data/payment-signed.bin"),
        Default::default(),
    )
    .unwrap();
    // Frozen Dogecoin Core regtest txid; unrelated to our hash implementation.
    let expected = "3cd139ff08015a742456f341bd5a6105954bef85c69ad3e581c429454b8e844a";
    assert_eq!(tx.txid().to_string(), expected);
    assert_eq!(HASHES.load(Ordering::Relaxed), 0);

    assert!(install_default_provider(&PROVIDER).is_ok());
    assert_eq!(tx.txid().to_string(), expected);
    assert!(HASHES.load(Ordering::Relaxed) > 0);

    // Unimplemented methods use software directly, without recursive dispatch.
    assert_eq!(
        crypto_provider().sha256_parts(&[b"a", b"", b"bc"]),
        SoftwareCrypto.sha256(b"abc")
    );
    assert!(install_default_provider(&SoftwareCrypto).is_err());
    let before = HASHES.load(Ordering::Relaxed);
    assert_eq!(tx.txid().to_string(), expected);
    assert!(HASHES.load(Ordering::Relaxed) > before);
}
