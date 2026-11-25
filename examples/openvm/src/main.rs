//! One bounded workload; features select backends, never input or assertions.
use core::hint::black_box;
use planchet::{
    BaseHeader, DecodeLimits, TxRef, Txid,
    consensus::merkle::{MerkleError, merkle_root_checked},
    crypto::{VerifyError, verify_k256_prehash, verify_p256_prehash},
    hash160, keccak256, sha256, sha256d,
};

mod fixtures;
use fixtures::*;

#[cfg(target_os = "zkvm")]
openvm::init!();

struct Transcript {
    bytes: [u8; 2048],
    len: usize,
}

impl Transcript {
    fn append(&mut self, bytes: &[u8]) {
        let end = self.len.checked_add(bytes.len()).unwrap();
        self.bytes[self.len..end].copy_from_slice(bytes);
        self.len = end;
    }

    fn check(&mut self, actual: &[u8], expected: &[u8]) {
        assert_eq!(actual, expected);
        self.append(actual);
    }

    fn verdict(&mut self, passed: bool) {
        assert!(passed);
        self.append(&[u8::from(passed)]);
    }
}

type Verify = fn(&[u8], &[u8; 32], &[u8; 64]) -> Result<(), VerifyError>;

fn signatures(
    t: &mut Transcript,
    verify: Verify,
    key: &[u8; 65],
    compressed: &[u8; 33],
    signature: &[u8; 64],
) {
    let prehash = black_box(PREHASH);
    let signature = black_box(*signature);
    let key = black_box(*key);
    let compressed = black_box(*compressed);
    t.verdict(verify(&key, &prehash, &signature).is_ok());
    t.verdict(verify(&compressed, &prehash, &signature).is_ok());

    let mut wrong_prehash = prehash;
    wrong_prehash[0] ^= 1;
    t.verdict(verify(&key, &wrong_prehash, &signature).is_err());
    let mut wrong_signature = signature;
    wrong_signature[63] ^= 1;
    t.verdict(verify(&key, &prehash, &wrong_signature).is_err());
    t.verdict(verify(&key, &prehash, &black_box([0; 64])).is_err());
    let mut out_of_range = signature;
    out_of_range[..32].fill(0xff);
    t.verdict(verify(&key, &prehash, &out_of_range).is_err());
    let mut off_curve = [0; 65];
    off_curve[0] = 4;
    t.verdict(verify(&black_box(off_curve), &prehash, &signature).is_err());
    t.verdict(verify(black_box(&key[..32]), &prehash, &signature).is_err());
}

fn main() {
    let mut t = Transcript {
        bytes: [0; 2048],
        len: 0,
    };
    let repeated = black_box([0xa3; 1024]);
    let abc = black_box(*b"abc");
    for &(len, expected_sha, expected_double) in SHA_CASES {
        let input = if len == 3 { &abc[..] } else { &repeated[..len] };
        t.check(&sha256(black_box(input)), &expected_sha);
        t.check(&sha256d(black_box(input)), &expected_double);
    }
    for &(len, expected) in KECCAK_CASES {
        let input = if len == 3 { &abc[..] } else { &repeated[..len] };
        t.check(&keccak256(black_box(input)), &expected);
    }
    t.check(&hash160(black_box(&K256_COMPRESSED)), &HASH160);

    let genesis = black_box(include_bytes!("../fixtures/mainnet-genesis.bin"));
    let limits = DecodeLimits {
        max_tx_bytes: 256,
        max_inputs: 1,
        max_outputs: 1,
        max_script_bytes: 128,
        ..DecodeLimits::default()
    };
    let tx = TxRef::decode_exact(&genesis[81..], limits).unwrap();
    assert!(tx.is_coinbase());
    t.check(tx.txid().as_wire_bytes(), &GENESIS_TXID);
    let header = BaseHeader::decode_exact(&genesis[..80]).unwrap();
    assert_eq!(header.merkle_root.as_wire_bytes(), &GENESIS_TXID);
    t.check(header.block_id().as_wire_bytes(), &GENESIS_BLOCK_ID);

    let leaves = black_box(LEAVES).map(Txid::from_wire_bytes);
    t.check(
        merkle_root_checked(leaves).unwrap().as_wire_bytes(),
        &MERKLE_ROOT,
    );
    assert_eq!(
        merkle_root_checked([leaves[0], leaves[0]]),
        Err(MerkleError::Mutated)
    );
    assert_eq!(merkle_root_checked([]), Err(MerkleError::Empty));

    signatures(
        &mut t,
        verify_k256_prehash,
        &K256_SEC1,
        &K256_COMPRESSED,
        &K256_SIGNATURE,
    );
    signatures(
        &mut t,
        verify_p256_prehash,
        &P256_SEC1,
        &P256_COMPRESSED,
        &P256_SIGNATURE,
    );

    assert_eq!(t.len, 1028);
    let output = sha256(black_box(&t.bytes[..t.len]));
    assert_eq!(output, TRANSCRIPT_SHA256);
    #[cfg(target_os = "zkvm")]
    openvm::io::reveal_bytes32(output);
    println!("planchet-openvm workload-v1: all assertions passed; transcript={output:02x?}");
}
