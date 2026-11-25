#![cfg(all(feature = "local", feature = "psbt"))]
use planchet_consensus::{
    script::p2pkh_script,
    sighash::{
        SighashError, SighashType, historical_one, legacy_sighash, legacy_sighash_for_signing,
    },
    transaction::{PaymentBudget, PaymentError, Prevout, Transaction, TxIn, TxOut},
};
use planchet_primitives::{Hash160, OutPoint, hash160};
use planchet_psbt::{Error as PsbtError, PsbtLimits, PsbtV0};
use planchet_signer::{DigestSigner, Error as SignerError, LocalSigner, SignRequest};

fn signer() -> LocalSigner {
    // Public scalar-one test fixture only.
    let mut key = [0; 32];
    key[31] = 1;
    LocalSigner::from_bytes(&key).unwrap()
}

fn setup() -> (PsbtV0, Vec<Prevout>, PaymentBudget, Transaction) {
    let script = p2pkh_script(Hash160::from_wire_bytes(hash160(
        signer().public_key().as_bytes(),
    )))
    .to_vec();
    let parent = Transaction {
        version: 1,
        lock_time: 0,
        inputs: vec![TxIn {
            previous_output: OutPoint::NULL,
            script_sig: vec![0x51],
            sequence: u32::MAX,
        }],
        outputs: vec![
            TxOut {
                value: 200_000_000,
                script_pubkey: script.clone()
            };
            2
        ],
    };
    let prevouts: Vec<_> = (0..2)
        .map(|vout| Prevout::from_parent(OutPoint::new(parent.txid(), vout), &parent).unwrap())
        .collect();
    let unsigned = Transaction::builder(1, 0)
        .spend(prevouts[0].outpoint, 123)
        .spend(prevouts[1].outpoint, 456)
        .pay(script.clone(), 100_000_000)
        .pay(script, 100_000_000)
        .finish()
        .unwrap();
    let mut psbt = PsbtV0::from_unsigned(unsigned).unwrap();
    psbt.attach_parent(0, &parent).unwrap();
    psbt.attach_compact_prevout(1, &prevouts[1]).unwrap();
    let budget = PaymentBudget {
        max_fee: 200_000_000,
        min_fee_rate_koinu_per_kvb: 100_000_000,
    };
    (psbt, prevouts, budget, parent)
}

fn sign_all(psbt: &mut PsbtV0, prevouts: &[Prevout], budget: PaymentBudget, mode: SighashType) {
    for index in 0..prevouts.len() {
        let request = psbt
            .sign_request(
                index,
                prevouts,
                signer().public_key().as_bytes(),
                mode,
                budget,
            )
            .unwrap();
        let result = signer()
            .sign_prehash(&SignRequest::from_psbt(&request).unwrap())
            .unwrap();
        psbt.insert_verified_signature(
            &request,
            result.public_key.as_bytes(),
            result.signature.as_der(),
            result.sighash_type,
        )
        .unwrap();
    }
}

// Every mode must preserve unsigned bytes/opaque maps while producing scripts
// whose signatures and actual-size payment budget pass final extraction.
#[test]
fn six_modes_finalize_and_extract_with_parent_and_trusted_compact_prevouts() {
    for mode in [
        SighashType::All,
        SighashType::None,
        SighashType::Single,
        SighashType::AllAnyoneCanPay,
        SighashType::NoneAnyoneCanPay,
        SighashType::SingleAnyoneCanPay,
    ] {
        let (mut psbt, prevouts, budget, _) = setup();
        psbt.insert_global(vec![0x50], vec![1, 2, 3]).unwrap();
        psbt.insert_input(0, vec![0x51], vec![5, 4]).unwrap();
        psbt.insert_output(1, vec![0x52], vec![8, 9]).unwrap();
        for i in 0..2 {
            psbt.insert_input(i, vec![3], mode.to_u32().to_le_bytes().to_vec())
                .unwrap();
        }
        let original = psbt.clone();
        sign_all(&mut psbt, &prevouts, budget, mode);
        let signed = psbt.finalize_p2pkh(&prevouts, budget).unwrap();
        assert_eq!(signed.summary().fee, 200_000_000);
        assert_eq!(signed.summary().transaction_bytes, signed.encode().len());
        assert_eq!(psbt.unsigned_transaction(), original.unsigned_transaction());
        assert_eq!(psbt.global(), original.global());
        assert_eq!(psbt.outputs(), original.outputs());
        assert_eq!(psbt.inputs()[0].get(&[0x51]), Some(&[5, 4][..]));
        let decoded = PsbtV0::decode(&psbt.encode(), PsbtLimits::default()).unwrap();
        assert_eq!(decoded.extract(&prevouts, budget).unwrap(), signed);
        assert_eq!(
            signed
                .transaction()
                .inputs
                .iter()
                .map(|i| i.sequence)
                .collect::<Vec<_>>(),
            [123, 456]
        );
        assert_ne!(
            signed.transaction().txid(),
            original.unsigned_transaction().txid()
        );
    }
}

#[test]
fn external_results_validate_before_any_psbt_mutation() {
    let (mut psbt, prevouts, budget, _) = setup();
    let request = psbt
        .sign_request(
            0,
            &prevouts,
            signer().public_key().as_bytes(),
            SighashType::All,
            budget,
        )
        .unwrap();
    let local_request = SignRequest::from_psbt(&request).unwrap();
    let result = signer().sign_prehash(&local_request).unwrap();
    let original = psbt.encode();
    assert_eq!(
        psbt.insert_verified_signature(
            &request,
            result.public_key.as_bytes(),
            result.signature.as_der(),
            SighashType::None
        ),
        Err(PsbtError::SighashMismatch)
    );
    assert_eq!(psbt.encode(), original);
    let mut other_key = [0; 32];
    other_key[31] = 2;
    let other = LocalSigner::from_bytes(&other_key).unwrap();
    assert_eq!(
        other.sign_prehash(&local_request),
        Err(SignerError::WrongPublicKey)
    );
    assert_eq!(
        psbt.insert_verified_signature(
            &request,
            other.public_key().as_bytes(),
            result.signature.as_der(),
            SighashType::All
        ),
        Err(PsbtError::WrongPublicKey)
    );
    assert_eq!(psbt.encode(), original);
    for bad in [vec![], vec![0x30, 0], {
        let mut d = result.signature.as_der().to_vec();
        d.push(1);
        d
    }] {
        assert!(
            psbt.insert_verified_signature(
                &request,
                result.public_key.as_bytes(),
                &bad,
                SighashType::All
            )
            .is_err()
        );
        assert_eq!(psbt.encode(), original);
    }
    let other_request = psbt
        .sign_request(
            0,
            &prevouts,
            signer().public_key().as_bytes(),
            SighashType::None,
            budget,
        )
        .unwrap();
    let wrong_digest = signer()
        .sign_prehash(&SignRequest::from_psbt(&other_request).unwrap())
        .unwrap();
    assert_eq!(
        psbt.insert_verified_signature(
            &request,
            result.public_key.as_bytes(),
            wrong_digest.signature.as_der(),
            SighashType::All
        ),
        Err(PsbtError::InvalidSignature)
    );
    assert_eq!(psbt.encode(), original);
    let mut wrong_mode = result.clone();
    wrong_mode.sighash_type = SighashType::None;
    assert_eq!(
        local_request.validate_result(&wrong_mode),
        Err(SignerError::WrongMode)
    );
    let sig = k256::ecdsa::Signature::from_der(result.signature.as_der()).unwrap();
    let high =
        k256::ecdsa::Signature::from_scalars(sig.r().to_bytes(), (-*sig.s()).to_bytes()).unwrap();
    assert_eq!(
        psbt.insert_verified_signature(
            &request,
            result.public_key.as_bytes(),
            high.to_der().as_bytes(),
            SighashType::All
        ),
        Err(PsbtError::HighS)
    );
    assert_eq!(psbt.encode(), original);
    let mut modified = psbt.unsigned_transaction().clone();
    modified.outputs[0].value -= 1;
    let mut modified = PsbtV0::from_unsigned(modified).unwrap();
    let before = modified.encode();
    assert_eq!(
        modified.insert_verified_signature(
            &request,
            result.public_key.as_bytes(),
            result.signature.as_der(),
            SighashType::All
        ),
        Err(PsbtError::StaleRequest)
    );
    assert_eq!(modified.encode(), before);
}

#[test]
fn unchecked_final_fields_and_budget_failures_cannot_partially_finalize() {
    let (mut psbt, prevouts, budget, _) = setup();
    sign_all(&mut psbt, &prevouts, budget, SighashType::All);
    let original = psbt.encode();
    let impossible = PaymentBudget {
        min_fee_rate_koinu_per_kvb: u64::MAX,
        ..budget
    };
    assert!(psbt.finalize_p2pkh(&prevouts, impossible).is_err());
    assert_eq!(psbt.encode(), original);
    let signed = psbt.finalize_p2pkh(&prevouts, budget).unwrap();
    let mut forged = PsbtV0::from_unsigned(psbt.unsigned_transaction().clone()).unwrap();
    for (i, input) in signed.transaction().inputs.iter().enumerate() {
        let mut script = input.script_sig.clone();
        if i == 1 {
            script[10] ^= 1;
        }
        forged.insert_input(i, vec![7], script).unwrap();
    }
    let before = forged.encode();
    assert!(forged.extract(&prevouts, budget).is_err());
    assert!(forged.finalize_p2pkh(&prevouts, budget).is_err());
    assert_eq!(forged.encode(), before);
    let mut missing = PsbtV0::from_unsigned(psbt.unsigned_transaction().clone()).unwrap();
    let before = missing.encode();
    assert_eq!(
        missing.finalize_p2pkh(&prevouts, budget),
        Err(PsbtError::MissingSignature)
    );
    assert_eq!(missing.encode(), before);
}

#[test]
fn parent_compact_budget_and_template_validation() {
    let (mut psbt, prevouts, budget, mut parent) = setup();
    parent.lock_time = 1;
    let before = psbt.encode();
    assert!(psbt.attach_parent(0, &parent).is_err());
    assert_eq!(psbt.encode(), before);
    let mut wrong = prevouts.clone();
    wrong[1].output.value += 1;
    assert!(
        psbt.sign_request(
            0,
            &wrong,
            signer().public_key().as_bytes(),
            SighashType::All,
            budget
        )
        .is_err()
    );
    assert!(psbt.attach_compact_prevout(0, &wrong[1]).is_err());
    let too_small = PaymentBudget {
        max_fee: budget.max_fee - 1,
        ..budget
    };
    assert_eq!(
        psbt.sign_request(
            0,
            &prevouts,
            signer().public_key().as_bytes(),
            SighashType::All,
            too_small
        ),
        Err(PsbtError::Payment(PaymentError::FeeExceedsBudget))
    );
    let mut wrong = prevouts.clone();
    wrong[0].outpoint.vout = u32::MAX;
    assert!(
        psbt.sign_request(
            0,
            &wrong,
            signer().public_key().as_bytes(),
            SighashType::All,
            budget
        )
        .is_err()
    );
    psbt.insert_input(0, vec![4], vec![0x51]).unwrap();
    assert_eq!(
        psbt.sign_request(
            0,
            &prevouts,
            signer().public_key().as_bytes(),
            SighashType::All,
            budget
        ),
        Err(PsbtError::UnsupportedTemplate)
    );
    let mut tx = psbt.unsigned_transaction().clone();
    tx.inputs[1].previous_output = tx.inputs[0].previous_output;
    assert_eq!(
        budget.check(&tx, &prevouts, 300),
        Err(PaymentError::DuplicateInput)
    );
    tx.inputs[1].previous_output = prevouts[1].outpoint;
    tx.outputs[0].value = u64::MAX;
    assert_eq!(
        budget.check(&tx, &prevouts, 300),
        Err(PaymentError::InvalidAmount)
    );
    tx.outputs[0].value = 400_000_001;
    assert_eq!(
        budget.check(&tx, &prevouts, 300),
        Err(PaymentError::InsufficientFunds)
    );
}

#[test]
fn historical_single_edge_is_available_but_new_requests_refuse() {
    let (psbt, prevouts, _, _) = setup();
    let mut tx = psbt.unsigned_transaction().clone();
    tx.outputs.pop();
    for hash_type in [3, 0x83] {
        assert_eq!(
            legacy_sighash(&tx, 1, &prevouts[1].output.script_pubkey, hash_type),
            historical_one()
        );
    }
    // Independent ECDSA fixture: d=k=1, r=generator.x, s=r+2^248.
    // Historical ONE has raw digest 01 followed by 31 zero bytes, so its
    // ECDSA integer is 2^248. Both scalars are nonzero, in range and low S.
    let der = "3044022079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f8179802207abe667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
    let der: Vec<u8> = der
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(core::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect();
    let signature = planchet_signer::EcdsaSignature::from_der(&der).unwrap();
    planchet_signer::verify_historical(&signer().public_key(), historical_one(), &signature)
        .unwrap();
    assert_eq!(
        legacy_sighash_for_signing(
            &tx,
            1,
            &prevouts[1].output.script_pubkey,
            SighashType::Single
        ),
        Err(SighashError::SingleWithoutOutput)
    );
    let budget = PaymentBudget {
        max_fee: u64::MAX,
        min_fee_rate_koinu_per_kvb: 0,
    };
    assert_eq!(
        SignRequest::p2pkh(
            &tx,
            1,
            &prevouts,
            signer().public_key(),
            SighashType::Single,
            budget
        ),
        Err(SignerError::Sighash(SighashError::SingleWithoutOutput))
    );
    let psbt = PsbtV0::from_unsigned(tx).unwrap();
    assert_eq!(
        psbt.sign_request(
            1,
            &prevouts,
            signer().public_key().as_bytes(),
            SighashType::SingleAnyoneCanPay,
            budget
        ),
        Err(PsbtError::Sighash(SighashError::SingleWithoutOutput))
    );
    assert!(SighashType::from_u32(0x41).is_err());
}
