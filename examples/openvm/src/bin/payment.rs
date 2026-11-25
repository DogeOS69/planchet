//! Frozen Core-accepted regtest payment through the public facade.
use core::hint::black_box;
use hex_literal::hex;
use planchet::{
    Sighash,
    consensus::{
        sighash::legacy_sighash,
        transaction::{PaymentBudget, Prevout, Transaction},
    },
    psbt::PsbtV0,
    signer::{EcdsaSignature, PublicKey, verify_prehash},
};

// This package enables openvm/std: use the normal std main on host and guest.
#[cfg(target_os = "zkvm")]
openvm::init!();

const SIGNED: &[u8; 192] = include_bytes!("../../fixtures/payment-signed.bin");
const PARENT: &[u8; 226] = include_bytes!("../../fixtures/payment-parent.bin");
// Raw/wire order; RPC display is the reverse of these bytes.
const TXID: [u8; 32] = hex!("4a848e4b4529c481e5d39ac685ef4b9505615abd41f35624745a0108ff39d13c");

fn main() {
    let signed = Transaction::decode_exact(black_box(SIGNED), Default::default()).unwrap();
    let parent = Transaction::decode_exact(black_box(PARENT), Default::default()).unwrap();
    assert_eq!(signed.inputs.len(), 1);
    let prevout = Prevout::from_parent(signed.inputs[0].previous_output, &parent).unwrap();
    let mut unsigned = signed.clone();
    let script = core::mem::take(&mut unsigned.inputs[0].script_sig);
    let siglen = usize::from(script[0]);
    assert_eq!(script[siglen], 1); // SIGHASH_ALL byte follows DER.
    assert_eq!(script[siglen + 1], 33); // Compressed SEC1 push.
    let signature = EcdsaSignature::from_der(&script[1..siglen]).unwrap();
    let key = PublicKey::from_sec1_bytes(&script[siglen + 2..]).unwrap();
    let digest = legacy_sighash(&unsigned, 0, &prevout.output.script_pubkey, 1);
    verify_prehash(&key, digest, &signature).unwrap();
    assert!(
        verify_prehash(
            &key,
            Sighash::from_wire_bytes(black_box([1; 32])),
            &signature
        )
        .is_err()
    );

    let mut psbt = PsbtV0::from_unsigned(unsigned).unwrap();
    psbt.attach_parent(0, &parent).unwrap();
    psbt.insert_input(0, vec![7], script).unwrap(); // PSBT_IN_FINAL_SCRIPTSIG.
    let payment = psbt
        .finalize_p2pkh(
            &[prevout],
            PaymentBudget {
                max_fee: 1_000_000,
                min_fee_rate_koinu_per_kvb: 1000,
            },
        )
        .unwrap();
    assert_eq!(payment.encode(), SIGNED.as_slice());
    let txid = payment.transaction().txid().to_wire_bytes();
    assert_eq!(txid, TXID);
    #[cfg(target_os = "zkvm")]
    openvm::io::reveal_bytes32(txid);
    println!(
        "planchet-openvm payment: all assertions passed; txid=3cd139ff08015a742456f341bd5a6105954bef85c69ad3e581c429454b8e844a"
    );
}
