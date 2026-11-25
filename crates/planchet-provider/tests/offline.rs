use planchet_provider::{Error, check_raw_block};
const BLOCK: &[u8] = include_bytes!("fixtures/regtest-genesis.bin");
const GENESIS: &str = "3d2160a3b5dc4a9d62e7e66a295f70313ac808440ef7400d6c0772171ce973a5";
#[test]
fn offline_checks_core_genesis_and_rejects_wrong_anchor() {
    assert_eq!(
        check_raw_block(BLOCK, Some(GENESIS.parse().unwrap()))
            .unwrap()
            .block_hash
            .to_string(),
        GENESIS
    );
    assert!(matches!(
        check_raw_block(BLOCK, Some(planchet_primitives::BlockHash::ZERO)),
        Err(Error::HashMismatch { .. })
    ));
}
#[test]
fn offline_rejects_trailing_truncated_and_merkle_corrupt_bytes() {
    let mut trailing = BLOCK.to_vec();
    trailing.push(0);
    assert!(matches!(
        check_raw_block(&trailing, None),
        Err(Error::InvalidBlock { .. })
    ));
    assert!(matches!(
        check_raw_block(&BLOCK[..BLOCK.len() - 1], None),
        Err(Error::InvalidBlock { .. })
    ));
    let mut corrupt = BLOCK.to_vec();
    corrupt[40] ^= 1;
    assert!(matches!(
        check_raw_block(&corrupt, None),
        Err(Error::InvalidBlock {
            reason: "transaction Merkle root mismatch or mutation"
        })
    ));
}
