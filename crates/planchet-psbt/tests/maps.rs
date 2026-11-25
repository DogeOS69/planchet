#![cfg(feature = "alloc")]
use planchet_consensus::transaction::{Transaction, TxIn, TxOut};
use planchet_primitives::{OutPoint, Txid};
use planchet_psbt::{Error, PsbtLimits, PsbtV0};

fn psbt() -> PsbtV0 {
    PsbtV0::from_unsigned(Transaction {
        version: 1,
        inputs: vec![TxIn {
            previous_output: OutPoint::new(Txid::from_wire_bytes([0x42; 32]), 3),
            script_sig: vec![],
            sequence: 0xffff_fffe,
        }],
        outputs: vec![TxOut {
            value: 1,
            script_pubkey: vec![0x51],
        }],
        lock_time: 0,
    })
    .unwrap()
}

#[test]
fn unknown_keys_remain_ordered_and_conflicts_are_atomic() {
    let mut left = psbt();
    left.insert_global(vec![0xfc, 1, b'x', 0, 7], vec![0, 0xff])
        .unwrap();
    left.insert_input(0, vec![0xfd, 0x23, 1, 7], vec![3, 2, 1])
        .unwrap();
    left.insert_output(0, vec![0xfc, 1, b'z', 1], vec![8])
        .unwrap();
    let original = left.encode();
    let decoded = PsbtV0::decode(&original, PsbtLimits::default()).unwrap();
    assert_eq!(decoded.encode(), original);
    let mut right = psbt();
    right
        .insert_global(vec![0xfc, 1, b'y', 1], vec![0])
        .unwrap();
    right
        .insert_output(0, vec![0xfc, 1, b'z', 1], vec![9])
        .unwrap();
    assert_eq!(left.combine(&right), Err(Error::Conflict));
    assert_eq!(left.encode(), original);
    let mut compatible = psbt();
    compatible
        .insert_input(0, vec![0xfc, 1, b'u', 1], vec![5])
        .unwrap();
    left.combine(&compatible).unwrap();
    assert_eq!(left.global(), decoded.global());
    assert_eq!(left.outputs(), decoded.outputs());
    assert_eq!(
        left.inputs()[0].get(&[0xfd, 0x23, 1, 7]),
        Some(&[3, 2, 1][..])
    );
    let mut different = compatible.unsigned_transaction().clone();
    different.lock_time = 1;
    let before = left.encode();
    assert_eq!(
        left.combine(&PsbtV0::from_unsigned(different).unwrap()),
        Err(Error::DifferentTransaction)
    );
    assert_eq!(left.encode(), before);
}

#[test]
fn all_truncations_and_resource_limits_reject() {
    let bytes = psbt().encode();
    for len in 0..bytes.len() {
        assert!(
            PsbtV0::decode(&bytes[..len], PsbtLimits::default()).is_err(),
            "prefix {len}"
        );
    }
    assert!(
        PsbtV0::decode(
            &bytes,
            PsbtLimits {
                max_bytes: bytes.len() - 1,
                ..PsbtLimits::default()
            }
        )
        .is_err()
    );
    assert!(
        PsbtV0::decode(
            &bytes,
            PsbtLimits {
                max_value_bytes: 1,
                ..PsbtLimits::default()
            }
        )
        .is_err()
    );
    assert!(
        PsbtV0::decode(
            &bytes,
            PsbtLimits {
                max_entries_per_map: 0,
                ..PsbtLimits::default()
            }
        )
        .is_err()
    );
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert_eq!(
        PsbtV0::decode(&trailing, PsbtLimits::default()),
        Err(Error::MapCount)
    );
}

#[test]
fn compact_size_must_be_minimal_in_lengths_and_key_types() {
    let mut bytes = psbt().encode();
    bytes.splice(5..6, [0xfd, 1, 0]);
    assert!(PsbtV0::decode(&bytes, PsbtLimits::default()).is_err());
    assert!(
        psbt()
            .insert_input(0, vec![0xfd, 0x23, 0], vec![1])
            .is_err()
    );
    let mut bytes = psbt().encode();
    // Original global map key is length=1, type=0; supply the exact same key
    // twice before the terminator, even with the exact same value.
    let end = bytes.len() - 3;
    let global_entry = bytes[5..end].to_vec();
    bytes.splice(end..end, global_entry);
    assert_eq!(
        PsbtV0::decode(&bytes, PsbtLimits::default()),
        Err(Error::DuplicateKey)
    );
}

#[test]
fn ten_thousand_entries_preserve_wire_order_and_enforce_limit() {
    let mut bytes = psbt().encode();
    let insertion = bytes.len() - 2;
    let mut entries = vec![];
    for i in 0..10_000u32 {
        entries.extend_from_slice(&[5, 0x55]);
        entries.extend_from_slice(&i.to_le_bytes());
        entries.extend_from_slice(&[1, (i & 255) as u8]);
    }
    bytes.splice(insertion..insertion, entries);
    let parsed = PsbtV0::decode(&bytes, PsbtLimits::default()).unwrap();
    assert_eq!(parsed.inputs()[0].entries().len(), 10_000);
    assert_eq!(parsed.encode(), bytes);
    assert!(
        PsbtV0::decode(
            &bytes,
            PsbtLimits {
                max_entries_per_map: 9_999,
                ..PsbtLimits::default()
            }
        )
        .is_err()
    );
}
