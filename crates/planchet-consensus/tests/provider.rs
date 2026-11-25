#![cfg(feature = "crypto-backend")]

use planchet_consensus::{BlockRef, DecodeLimits, merkle_root_checked};
use planchet_crypto::{CryptoProvider, SoftwareCrypto, install_default_provider};
use planchet_primitives::Txid;
use std::sync::atomic::{AtomicUsize, Ordering};

static SHA_CALLS: AtomicUsize = AtomicUsize::new(0);
struct Provider;
static PROVIDER: Provider = Provider;
impl CryptoProvider for Provider {
    fn sha256(&self, input: &[u8]) -> [u8; 32] {
        SHA_CALLS.fetch_add(1, Ordering::Relaxed);
        SoftwareCrypto.sha256(input)
    }
}

#[test]
fn consensus_ids_and_merkle_pairs_use_the_application_provider() {
    assert!(install_default_provider(&PROVIDER).is_ok());
    let root = merkle_root_checked([
        Txid::from_wire_bytes([1; 32]),
        Txid::from_wire_bytes([2; 32]),
    ])
    .unwrap();
    // Python hashlib.sha256(sha256(bytes([1])*32+bytes([2])*32).digest()).
    assert_eq!(
        root.to_wire_bytes(),
        [
            57, 206, 32, 190, 222, 130, 201, 107, 137, 8, 190, 196, 161, 87, 176, 156, 84, 155, 61,
            185, 11, 155, 71, 75, 218, 154, 233, 185, 3, 3, 16, 180,
        ]
    );
    assert_eq!(SHA_CALLS.load(Ordering::Relaxed), 2);
    let block = BlockRef::decode_exact(
        include_bytes!("fixtures/regtest-genesis.bin"),
        DecodeLimits::default(),
    )
    .unwrap();
    block.header().block_id();
    assert_eq!(SHA_CALLS.load(Ordering::Relaxed), 4);
    block.check_tx_merkle_root().unwrap();
    assert!(SHA_CALLS.load(Ordering::Relaxed) >= 6);
}
