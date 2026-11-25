//! Independent fixed fixtures protect byte order, signed-wire IDs, layout,
//! parent witness handling, and exact resource/consumption contracts.
use planchet_consensus::{
    AuxPowRef, BaseHeader, BlockRef, DecodeError, DecodeLimits, MerkleError, ParentCoinbaseRef,
    TxRef, WireHeader, compact_size::*, merkle_root_checked,
};
use planchet_primitives::Txid;

const FIXTURES: &[(&str, &[u8])] = &[
    (
        "mainnet-genesis.bin",
        include_bytes!("fixtures/mainnet-genesis.bin"),
    ),
    (
        "testnet-genesis.bin",
        include_bytes!("fixtures/testnet-genesis.bin"),
    ),
    (
        "regtest-genesis.bin",
        include_bytes!("fixtures/regtest-genesis.bin"),
    ),
    ("regtest-1.bin", include_bytes!("fixtures/regtest-1.bin")),
    (
        "regtest-105.bin",
        include_bytes!("fixtures/regtest-105.bin"),
    ),
    (
        "regtest-106-auxpow.bin",
        include_bytes!("fixtures/regtest-106-auxpow.bin"),
    ),
    (
        "dogeos-regtest-429.bin",
        include_bytes!("fixtures/dogeos-regtest-429.bin"),
    ),
    (
        "dogeos-regtest-430.bin",
        include_bytes!("fixtures/dogeos-regtest-430.bin"),
    ),
    (
        "dogeos-regtest-431.bin",
        include_bytes!("fixtures/dogeos-regtest-431.bin"),
    ),
    (
        "dogeos-regtest-432.bin",
        include_bytes!("fixtures/dogeos-regtest-432.bin"),
    ),
    (
        "dogeos-regtest-433.bin",
        include_bytes!("fixtures/dogeos-regtest-433.bin"),
    ),
    (
        "dogeos-regtest-434.bin",
        include_bytes!("fixtures/dogeos-regtest-434.bin"),
    ),
];
const AUX: &[u8] = include_bytes!("fixtures/regtest-106-auxpow.bin");
const WITNESS: &[u8] = include_bytes!("fixtures/structural-witness-header.bin");

fn hex(s: &str) -> Vec<u8> {
    assert_eq!(s.len() % 2, 0);
    s.as_bytes()
        .chunks_exact(2)
        .map(|p| u8::from_str_radix(core::str::from_utf8(p).unwrap(), 16).unwrap())
        .collect()
}
fn rpc(s: &str) -> [u8; 32] {
    let mut bytes: [u8; 32] = hex(s).try_into().unwrap();
    bytes.reverse();
    bytes
}
fn limits() -> DecodeLimits {
    DecodeLimits::default()
}

#[test]
fn core_and_current_fixture_cross_checks() {
    // Expected values were frozen using Core genesis assertions and an
    // independent Python hashlib/struct reader, not this crate's decoder.
    for line in include_str!("fixtures/blocks.tsv")
        .lines()
        .filter(|line| !line.starts_with('#'))
    {
        let fields: Vec<_> = line.split('\t').collect();
        let bytes = FIXTURES
            .iter()
            .find(|(name, _)| *name == fields[0])
            .unwrap()
            .1;
        let block = BlockRef::decode_exact(bytes, limits()).unwrap();
        assert_eq!(block.bytes(), bytes);
        assert_eq!(
            block.header().block_id().to_wire_bytes(),
            rpc(fields[1]),
            "{}",
            fields[0]
        );
        assert_eq!(
            block.tx_merkle_root().unwrap().to_wire_bytes(),
            rpc(fields[2])
        );
        block.check_tx_merkle_root().unwrap();
        let header_len: usize = fields[3].parse().unwrap();
        assert_eq!(block.header().bytes(), &bytes[..header_len]);
        assert_eq!(block.header().base().encode(), bytes[..80]);
        let mut encoded = vec![0xa5; header_len + 3];
        assert_eq!(
            block.header().encode_into(&mut encoded).unwrap(),
            header_len
        );
        assert_eq!(&encoded[..header_len], &bytes[..header_len]);
        assert_eq!(&encoded[header_len..], &[0xa5; 3]);
        let txids: Vec<_> = fields[4].split(',').map(rpc).collect();
        assert_eq!(
            block
                .txids()
                .map(|id| id.to_wire_bytes())
                .collect::<Vec<_>>(),
            txids
        );
        assert_eq!(block.tx_count(), txids.len());
        for (tx, expected_values) in block.transactions().zip(fields[5].split('|')) {
            let expected: Vec<u64> = if expected_values == "-" {
                vec![]
            } else {
                expected_values
                    .split(',')
                    .map(|s| s.parse().unwrap())
                    .collect()
            };
            assert_eq!(
                tx.outputs().map(|out| out.value()).collect::<Vec<_>>(),
                expected
            );
            assert_eq!(TxRef::decode_exact(tx.bytes(), limits()).unwrap(), tx);
            assert_eq!(tx.inputs().len(), tx.input_count());
            assert_eq!(tx.outputs().len(), tx.output_count());
            for input in tx.inputs() {
                assert!(core::ptr::eq(
                    input.script_sig(),
                    &tx.bytes()[input.script_sig_range()]
                ));
            }
            for output in tx.outputs() {
                assert!(core::ptr::eq(
                    output.script_pubkey(),
                    &tx.bytes()[output.script_pubkey_range()]
                ));
                assert_eq!(output.value_wire_bytes(), output.value().to_le_bytes());
            }
        }
    }
}

#[test]
fn fixture_native_chain_links_and_iterator_contracts() {
    let mut prior = None;
    for (_, bytes) in &FIXTURES[6..] {
        let block = BlockRef::decode_exact(bytes, limits()).unwrap();
        if let Some(prior) = prior {
            assert_eq!(block.header().base().prev_blockhash, prior);
        }
        prior = Some(block.header().block_id());
        let mut iter = block.transactions();
        assert_eq!(iter.clone().count(), iter.len());
        while iter.next().is_some() {}
        assert_eq!(iter.len(), 0);
        assert!(iter.next().is_none());
        assert!(iter.next().is_none());
    }
}

#[test]
fn prefix_limits_cover_only_the_consumed_transaction() {
    let block = BlockRef::decode_exact(FIXTURES[4].1, limits()).unwrap();
    let txs: Vec<_> = block.transactions().collect();
    let mut joined = txs[0].bytes().to_vec();
    joined.extend_from_slice(txs[1].bytes());
    let mut budget = limits();
    budget.max_tx_bytes = txs[0].bytes().len();
    let (tx, consumed) = TxRef::decode_prefix(&joined, budget).unwrap();
    assert_eq!(consumed, txs[0].bytes().len());
    assert_eq!(tx, txs[0]);
    assert!(matches!(
        TxRef::decode_exact(&joined, budget),
        Err(DecodeError::LimitExceeded { .. })
    ));
    assert!(matches!(
        TxRef::decode_exact(&joined, limits()),
        Err(DecodeError::TrailingBytes { .. })
    ));
}

#[test]
fn unsigned_legacy_mode_permits_empty_inputs_without_witness_interpretation() {
    // Core SERIALIZE_TRANSACTION_NO_WITNESS / PSBT context: empty vin,
    // one output worth one koinu to OP_TRUE, locktime zero. 00 01 here
    // means input/output counts; it is not interpreted as a witness marker.
    let bytes = hex("0100000000010100000000000000015100000000");
    let unsigned = TxRef::decode_unsigned_exact(&bytes, limits()).unwrap();
    assert_eq!(unsigned.input_count(), 0);
    assert_eq!(unsigned.inputs().len(), 0);
    assert_eq!(unsigned.output_count(), 1);
    assert_eq!(unsigned.outputs().next().unwrap().value(), 1);
    assert_eq!(unsigned.outputs().next().unwrap().script_pubkey(), &[0x51]);
    assert!(!unsigned.is_coinbase());
    assert_eq!(
        TxRef::decode_exact(&bytes, limits()),
        Err(DecodeError::WitnessNotAllowed)
    );
    let empty = hex("01000000000000000000");
    let empty_ref = TxRef::decode_unsigned_exact(&empty, limits()).unwrap();
    assert_eq!((empty_ref.input_count(), empty_ref.output_count()), (0, 0));
    assert_eq!(
        TxRef::decode_exact(&empty, limits()),
        Err(DecodeError::MissingInputs)
    );
    assert_eq!(
        ParentCoinbaseRef::decode_exact(&empty, limits()),
        Err(DecodeError::NotCoinbase)
    );
    let mut trailing = empty.clone();
    trailing.push(0);
    assert!(matches!(
        TxRef::decode_unsigned_exact(&trailing, limits()),
        Err(DecodeError::TrailingBytes { .. })
    ));
    assert!(
        TxRef::decode_unsigned_exact(
            &empty,
            DecodeLimits {
                max_tx_bytes: 9,
                ..limits()
            }
        )
        .is_err()
    );
    let mut block = FIXTURES[0].1[..80].to_vec();
    block.push(1);
    block.extend_from_slice(&bytes);
    assert!(BlockRef::decode_exact(&block, limits()).is_err());
}

#[test]
fn accepted_auxpow_with_zero_parent_outputs_and_both_branch_views() {
    let block = BlockRef::decode_exact(AUX, limits()).unwrap();
    let header = block.header();
    let aux = header.auxpow().unwrap();
    assert_eq!(header.bytes().len(), 297);
    assert_eq!(aux.coinbase().output_count(), 0);
    assert_eq!(aux.coinbase().input_count(), 1);
    assert!(!aux.coinbase().has_witness_encoding());
    assert_eq!(
        aux.coinbase().txid().to_wire_bytes(),
        rpc(include_str!("fixtures/parent-txid.txt").trim())
    );
    assert!(aux.coinbase_branch().is_empty());
    assert!(aux.chain_branch().is_empty());
    assert_eq!(aux.coinbase_index(), 0);
    assert_eq!(aux.chain_index(), 0);
    assert_eq!(
        AuxPowRef::decode_exact(aux.bytes(), limits()).unwrap(),
        *aux
    );
    assert_eq!(
        BaseHeader::decode_exact(&header.bytes()[..80]).unwrap(),
        *header.base()
    );
    assert!(WireHeader::decode_exact(&header.bytes()[..80], limits()).is_err());
    let (prefix, consumed) = WireHeader::decode_prefix(AUX, limits()).unwrap();
    assert_eq!(prefix, *header);
    assert_eq!(consumed, 297);
    assert!(matches!(
        WireHeader::decode_exact(AUX, limits()),
        Err(DecodeError::TrailingBytes { .. })
    ));
    let mut short = vec![0; 296];
    assert!(matches!(
        header.encode_into(&mut short),
        Err(DecodeError::BufferTooSmall { needed: 297, .. })
    ));
}

#[test]
fn witness_parent_preserves_all_bytes_and_excludes_witness_from_txid() {
    // Synthetic structural fixture derived from accepted 106, not an assertion
    // that altered branches/witness still form a valid mining commitment.
    let header = WireHeader::decode_exact(WITNESS, limits()).unwrap();
    let aux = header.auxpow().unwrap();
    let parent = aux.coinbase();
    assert!(parent.has_witness_encoding());
    assert_eq!(parent.output_count(), 0);
    assert_eq!(
        parent.txid().to_wire_bytes(),
        rpc(include_str!("fixtures/parent-txid.txt").trim())
    );
    let items: Vec<_> = parent.witness_items().collect();
    assert_eq!(
        items,
        vec![(0..32).collect::<Vec<u8>>().as_slice(), &[0xde, 0xad]]
    );
    assert_eq!(
        aux.coinbase_branch().hashes().collect::<Vec<_>>(),
        vec![
            core::array::from_fn(|i| i as u8),
            core::array::from_fn(|i| 32 + i as u8)
        ]
    );
    assert_eq!(
        aux.chain_branch().hashes().collect::<Vec<_>>(),
        vec![core::array::from_fn(|i| 64 + i as u8)]
    );
    assert_eq!((aux.coinbase_index(), aux.chain_index()), (3, 1));
    assert_eq!(
        TxRef::decode_exact(parent.bytes(), limits()),
        Err(DecodeError::WitnessNotAllowed)
    );
    let mut reencoded = vec![0; WITNESS.len()];
    header.encode_into(&mut reencoded).unwrap();
    assert_eq!(reencoded, WITNESS);
    let legacy = BlockRef::decode_exact(AUX, limits()).unwrap();
    assert_eq!(header.block_id(), legacy.header().block_id());
    let mut changed = parent.bytes().to_vec();
    let index = parent.witness_range().end - 1;
    changed[index] ^= 1;
    assert_eq!(
        ParentCoinbaseRef::decode_exact(&changed, limits())
            .unwrap()
            .txid(),
        parent.txid()
    );
    let mut empty = parent.bytes()[..parent.witness_range().start].to_vec();
    empty.push(0);
    empty.extend_from_slice(&parent.lock_time().to_le_bytes());
    assert_eq!(
        ParentCoinbaseRef::decode_exact(&empty, limits())
            .unwrap()
            .txid(),
        parent.txid()
    );
}

#[test]
fn compactsize_independent_boundaries_minimality_and_bounds() {
    let cases: &[(u64, &str)] = &[
        (0, "00"),
        (252, "fc"),
        (253, "fdfd00"),
        (65535, "fdffff"),
        (65536, "fe00000100"),
        (0xffff_ffff, "feffffffff"),
        (0x1_0000_0000, "ff0000000001000000"),
        (u64::MAX, "ffffffffffffffffff"),
    ];
    for &(n, h) in cases {
        let raw = hex(h);
        assert_eq!(decode_compact_size(&raw, u64::MAX).unwrap(), (n, raw.len()));
        let mut out = [0xa5; 10];
        let size = encode_compact_size(n, &mut out).unwrap();
        assert_eq!(&out[..size], raw);
        assert_eq!(out[size], 0xa5);
        assert_eq!(compact_size_len(n), size);
        for cut in 0..raw.len() {
            assert!(matches!(
                decode_compact_size(&raw[..cut], u64::MAX),
                Err(DecodeError::UnexpectedEof { .. })
            ));
        }
        if n > 0 {
            assert!(matches!(
                decode_compact_size(&raw, n - 1),
                Err(DecodeError::LimitExceeded { .. })
            ));
        }
    }
    for h in ["fdfc00", "feffff0000", "ffffffffff00000000"] {
        assert!(matches!(
            decode_compact_size(&hex(h), u64::MAX),
            Err(DecodeError::NonMinimalCompactSize { .. })
        ));
    }
}

#[test]
fn every_nested_compactsize_uses_minimal_encoding() {
    // Fixture offsets come from their literal construction, independently of
    // production range accessors. Replacing any one-byte count with fd is a
    // redundant representation of exactly the same count.
    for offset in [4, 41, 49, 58] {
        let mut tx = raw_tx();
        let value = tx[offset];
        tx.splice(offset..offset + 1, [0xfd, value, 0]);
        assert!(matches!(
            TxRef::decode_exact(&tx, limits()),
            Err(DecodeError::NonMinimalCompactSize { .. })
        ));
    }
    for offset in [86, 123, 172, 173, 174, 207, 246, 315] {
        let mut header = WITNESS.to_vec();
        let value = header[offset];
        header.splice(offset..offset + 1, [0xfd, value, 0]);
        assert!(
            matches!(
                WireHeader::decode_exact(&header, limits()),
                Err(DecodeError::NonMinimalCompactSize { .. })
            ),
            "offset {offset}"
        );
    }
    let mut block = FIXTURES[0].1.to_vec();
    block.splice(80..81, [0xfd, 1, 0]);
    assert!(matches!(
        BlockRef::decode_exact(&block, limits()),
        Err(DecodeError::NonMinimalCompactSize { .. })
    ));
}

// This byte-exact structural transaction deliberately preserves a nonminimal
// Script push (4c 01 42), negative wire-value bits, and high version/locktime bits.
fn raw_tx() -> Vec<u8> {
    hex(concat!(
        "ffffffff01",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "ffffffff034c0142feffffff01ffffffffffffffff034c0142ffffffff"
    ))
}

#[test]
fn scripts_and_integer_bits_are_preserved_without_amount_or_script_policy() {
    let raw = raw_tx();
    let tx = TxRef::decode_exact(&raw, limits()).unwrap();
    assert_eq!(tx.version(), -1);
    assert_eq!(tx.version_bits(), u32::MAX);
    assert_eq!(tx.lock_time(), u32::MAX);
    let input = tx.inputs().next().unwrap();
    assert!(tx.is_coinbase());
    assert_eq!(input.sequence(), 0xffff_fffe);
    assert_eq!(input.script_sig(), &[0x4c, 1, 0x42]);
    assert_eq!(input.script_sig_range(), 42..45);
    let output = tx.outputs().next().unwrap();
    assert_eq!(output.value(), u64::MAX);
    assert_eq!(output.script_pubkey(), &[0x4c, 1, 0x42]);
    assert_eq!(output.script_pubkey_range(), 59..62);
    // Independently generated with Python hashlib; includes the signature bytes.
    assert_eq!(
        tx.txid().to_wire_bytes(),
        rpc("32a797edbfd072b8dfe47358924ea219da6dba9c496851b051a9c5d18af6af73")
    );
}

#[test]
fn exact_decoders_reject_all_truncations_and_trailing_bytes() {
    for &(_, bytes) in FIXTURES {
        for cut in 0..bytes.len() {
            assert!(
                BlockRef::decode_exact(&bytes[..cut], limits()).is_err(),
                "block cut {cut}"
            );
        }
        let mut tail = bytes.to_vec();
        tail.push(0);
        assert!(matches!(
            BlockRef::decode_exact(&tail, limits()),
            Err(DecodeError::TrailingBytes { .. })
        ));
        let block = BlockRef::decode_exact(bytes, limits()).unwrap();
        for tx in block.transactions() {
            for cut in 0..tx.bytes().len() {
                assert!(
                    TxRef::decode_exact(&tx.bytes()[..cut], limits()).is_err(),
                    "tx cut {cut}"
                );
            }
        }
    }
    for cut in 0..WITNESS.len() {
        assert!(WireHeader::decode_exact(&WITNESS[..cut], limits()).is_err());
    }
}

#[test]
fn budgets_and_hostile_counts_fail_before_large_loops_or_allocations() {
    let raw = raw_tx();
    for budget in [
        DecodeLimits {
            max_tx_bytes: raw.len() - 1,
            ..limits()
        },
        DecodeLimits {
            max_inputs: 0,
            ..limits()
        },
        DecodeLimits {
            max_outputs: 0,
            ..limits()
        },
        DecodeLimits {
            max_script_bytes: 2,
            ..limits()
        },
    ] {
        assert!(matches!(
            TxRef::decode_exact(&raw, budget),
            Err(DecodeError::LimitExceeded { .. })
        ));
    }
    for budget in [
        DecodeLimits {
            max_block_bytes: AUX.len() - 1,
            ..limits()
        },
        DecodeLimits {
            max_header_bytes: 296,
            ..limits()
        },
        DecodeLimits {
            max_parent_coinbase_bytes: 94,
            ..limits()
        },
        DecodeLimits {
            max_block_txs: 0,
            ..limits()
        },
    ] {
        assert!(BlockRef::decode_exact(AUX, budget).is_err());
    }
    for budget in [
        DecodeLimits {
            max_merkle_branch_hashes: 1,
            ..limits()
        },
        DecodeLimits {
            max_witness_items: 1,
            ..limits()
        },
        DecodeLimits {
            max_witness_item_bytes: 31,
            ..limits()
        },
        DecodeLimits {
            max_witness_bytes: 36,
            ..limits()
        },
    ] {
        assert!(matches!(
            WireHeader::decode_exact(WITNESS, budget),
            Err(DecodeError::LimitExceeded { .. })
        ));
    }
    let mut hostile = vec![1, 0, 0, 0];
    hostile.extend_from_slice(&[0xff; 9]);
    assert!(TxRef::decode_prefix(&hostile, limits()).is_err());
    let mut block = FIXTURES[0].1[..80].to_vec();
    block.extend_from_slice(&[0xff; 9]);
    assert!(
        BlockRef::decode_exact(
            &block,
            DecodeLimits {
                max_block_txs: usize::MAX,
                ..limits()
            }
        )
        .is_err()
    );
    let mut outputs = raw[..49].to_vec();
    outputs.extend_from_slice(&[0xff; 9]);
    assert!(
        TxRef::decode_exact(
            &outputs,
            DecodeLimits {
                max_outputs: usize::MAX,
                ..limits()
            }
        )
        .is_err()
    );
    let mut branch = WITNESS[..246].to_vec();
    branch.extend_from_slice(&[0xff; 9]);
    assert!(
        WireHeader::decode_exact(
            &branch,
            DecodeLimits {
                max_merkle_branch_hashes: usize::MAX,
                ..limits()
            }
        )
        .is_err()
    );
}

#[test]
fn header_flag_parent_flags_and_coinbase_shape_are_checked() {
    let mut truncated = AUX[..80].to_vec();
    assert!(WireHeader::decode_exact(&truncated, limits()).is_err());
    truncated[1] &= !1;
    assert!(WireHeader::decode_exact(&truncated, limits()).is_ok());
    let mut mismatch = AUX[..297].to_vec();
    mismatch[1] &= !1;
    assert!(matches!(
        WireHeader::decode_exact(&mismatch, limits()),
        Err(DecodeError::TrailingBytes { .. })
    ));
    for flags in [2, 3, 0x80, 0xff] {
        let mut bad = WITNESS.to_vec();
        bad[85] = flags;
        assert!(matches!(
            WireHeader::decode_exact(&bad, limits()),
            Err(DecodeError::UnknownWitnessFlags { .. })
        ));
    }
    let mut parent = WITNESS.to_vec();
    parent[87] = 1;
    assert_eq!(
        WireHeader::decode_exact(&parent, limits()),
        Err(DecodeError::NotCoinbase)
    );
    let mut empty = FIXTURES[0].1[..80].to_vec();
    empty.push(0);
    assert_eq!(
        BlockRef::decode_exact(&empty, limits()),
        Err(DecodeError::EmptyBlock)
    );
}

#[test]
fn mutation_is_rejected_at_leaf_and_internal_levels_while_odd_padding_is_valid() {
    let leaves: Vec<_> = (1..=6).map(|n| Txid::from_wire_bytes([n; 32])).collect();
    // Fixed roots independently calculated with Python hashlib (see provenance).
    for (count, expected) in [
        (
            1,
            "0101010101010101010101010101010101010101010101010101010101010101",
        ),
        (
            3,
            "223e023fadf1f053df26988871f893c821c28edf77d64a955e6c2a02d547bdac",
        ),
        (
            6,
            "7b66d521a8037fd37d8730a5a77b304c0994bf45fc6e225cb79073f087cf97e9",
        ),
    ] {
        assert_eq!(
            merkle_root_checked(leaves[..count].iter().copied())
                .unwrap()
                .to_wire_bytes(),
            hex(expected).as_slice()
        );
    }
    assert_eq!(merkle_root_checked([]), Err(MerkleError::Empty));
    assert_eq!(
        merkle_root_checked([leaves[0], leaves[0]]),
        Err(MerkleError::Mutated)
    );
    let mut duplicated = leaves[..3].to_vec();
    duplicated.push(leaves[2]);
    assert_eq!(merkle_root_checked(duplicated), Err(MerkleError::Mutated));
    let mut duplicated = leaves.clone();
    duplicated.extend_from_slice(&leaves[4..]);
    assert_eq!(merkle_root_checked(duplicated), Err(MerkleError::Mutated));
    // Repeated nonsibling leaves are not automatically the mutated-sibling case.
    assert!(merkle_root_checked([leaves[0], leaves[1], leaves[0]]).is_ok());
    let mut bad_root = FIXTURES[0].1.to_vec();
    bad_root[36] ^= 1;
    assert!(matches!(
        BlockRef::decode_exact(&bad_root, limits())
            .unwrap()
            .check_tx_merkle_root(),
        Err(MerkleError::RootMismatch { .. })
    ));
}

#[test]
fn block_merkle_check_rejects_mutated_suffixes_even_when_the_header_root_matches() {
    // Native structural blocks, independently frozen roots. This protects the
    // integration between ordered block iteration and whole-tree checking.
    for (count, root, repeat) in [
        (
            3,
            "9b34dd41692bf330ff1c16246a5a0c892ffbb2fb3882ad7019ceca674f8e48cb",
            1,
        ),
        (
            6,
            "fb3c3462cc6df1a4a2f8bd482c8212f5ede123a5c4c8b2dd516ed008f6130fa6",
            2,
        ),
    ] {
        let txs: Vec<_> = (1..=count)
            .map(|lock: u32| {
                let mut tx = raw_tx();
                let lock_start = tx.len() - 4;
                tx[lock_start..].copy_from_slice(&lock.to_le_bytes());
                tx
            })
            .collect();
        let mut header = FIXTURES[0].1[..80].to_vec();
        header[36..68].copy_from_slice(&hex(root));
        let mut real = header.clone();
        real.push(count as u8);
        for tx in &txs {
            real.extend_from_slice(tx);
        }
        BlockRef::decode_exact(&real, limits())
            .unwrap()
            .check_tx_merkle_root()
            .unwrap();
        let mut mutated = header;
        mutated.push((count + repeat) as u8);
        for tx in txs
            .iter()
            .chain(txs[count as usize - repeat as usize..].iter())
        {
            mutated.extend_from_slice(tx);
        }
        assert_eq!(
            BlockRef::decode_exact(&mutated, limits())
                .unwrap()
                .check_tx_merkle_root(),
            Err(MerkleError::Mutated)
        );
    }
}
