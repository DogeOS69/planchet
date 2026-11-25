#![cfg(feature = "crypto-backend")]

use planchet_crypto::{CryptoProvider, SoftwareCrypto, install_default_provider};
use std::sync::atomic::{AtomicUsize, Ordering};

static SHA_CALLS: AtomicUsize = AtomicUsize::new(0);
static PARTS_CALLS: AtomicUsize = AtomicUsize::new(0);
struct Provider;
static PROVIDER: Provider = Provider;

impl CryptoProvider for Provider {
    fn sha256(&self, input: &[u8]) -> [u8; 32] {
        SHA_CALLS.fetch_add(1, Ordering::Relaxed);
        SoftwareCrypto.sha256(input)
    }
    fn sha256_parts(&self, parts: &[&[u8]]) -> [u8; 32] {
        PARTS_CALLS.fetch_add(1, Ordering::Relaxed);
        SoftwareCrypto.sha256_parts(parts)
    }
}

#[test]
fn ordinary_hashes_use_provider_for_both_rounds_and_multipart_input() {
    use planchet_primitives::{hash160, sha256, sha256_parts, sha256d, sha256d_parts};
    assert!(install_default_provider(&PROVIDER).is_ok());
    assert_eq!(sha256(b"abc"), SoftwareCrypto.sha256(b"abc"));
    assert_eq!(SHA_CALLS.load(Ordering::Relaxed), 1);
    sha256d(b"abc");
    assert_eq!(SHA_CALLS.load(Ordering::Relaxed), 3);
    hash160(b"abc");
    assert_eq!(SHA_CALLS.load(Ordering::Relaxed), 4);
    assert_eq!(sha256_parts(&[b"a", b"bc"]), SoftwareCrypto.sha256(b"abc"));
    assert_eq!(PARTS_CALLS.load(Ordering::Relaxed), 1);
    sha256d_parts(&[b"a", b"", b"bc"]);
    assert_eq!(PARTS_CALLS.load(Ordering::Relaxed), 2);
    assert_eq!(SHA_CALLS.load(Ordering::Relaxed), 5);
}
