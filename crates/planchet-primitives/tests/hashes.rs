//! Fixed independent vectors; see VECTORS.md for provenance.
use planchet_primitives::{hash160, sha256, sha256d, sha256d_parts};

fn hex<const N: usize>(text: &str) -> [u8; N] {
    assert_eq!(text.len(), N * 2);
    core::array::from_fn(|i| u8::from_str_radix(&text[2 * i..2 * i + 2], 16).unwrap())
}

#[test]
fn sha256_known_answers_and_multipart_order() {
    assert_eq!(
        sha256(b""),
        hex("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
    );
    assert_eq!(
        sha256(b"abc"),
        hex("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
    );
    let empty = hex("5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456");
    assert_eq!(sha256d_parts(&[]), empty);
    assert_eq!(sha256d_parts(&[b"", b""]), empty);
    let abc = hex("4f8b42c22dd3729b519ba6f68d2da7cc5b2d606d05daed5ad5128cc03e6c6358");
    for parts in [
        &[b"abc".as_slice()][..],
        &[b"".as_slice(), b"abc", b""],
        &[b"a".as_slice(), b"b", b"c"],
        &[b"ab".as_slice(), b"", b"c"],
        &[b"".as_slice(), b"a", b"bc"],
    ] {
        assert_eq!(sha256d_parts(parts), abc);
    }
}

#[test]
fn sha256_padding_alignment_and_streamed_parts() {
    // Each expected value was generated outside Rust using Python hashlib.
    let vectors = [
        (
            55,
            "9f4390f8d30c2dd92ec9f095b65e2b9ae9b0a925a5258e241c9f1e910f734318",
            "566dbb7f0f129482d449b7a4b971b1302f13a1a5e1faee904a0a270b2b6f5a7d",
            "e23716d6140e7f616ed0784636820792fc66e0ba",
        ),
        (
            56,
            "b35439a4ac6f0948b6d6f9e3c6af0f5f590ce20f1bde7090ef7970686ec6738a",
            "122cf0fa8f81dae14842491eedeab26374370514f6c4413bcc32352ae586b39e",
            "e1dcb0b473950f27c45e65c0cdbe2ce6e80f7794",
        ),
        (
            63,
            "7d3e74a05d7db15bce4ad9ec0658ea98e3f06eeecf16b4c6fff2da457ddc2f34",
            "54f57e8b7d0ed00e442facf36dfa95ce6eb5df391bb7b198a4a3c728b8ba6e76",
            "ef2fc29f583db8d0cdb43916d0c6f46a3ae0b9bb",
        ),
        (
            64,
            "ffe054fe7ae0cb6dc65c3af9b61d5209f439851db43d0ba5997337df154668eb",
            "64d28424725a6f219efb17d6f8e4036719bf9e1a8ec2388c22cfb5fc412d46bc",
            "57591c6b8f00df7d36a642cc94021dda9ccd43fc",
        ),
        (
            65,
            "635361c48bb9eab14198e76ea8ab7f1a41685d6ad62aa9146d301d4f17eb0ae0",
            "fb183eb69ec26b94dbc6ae9ee468e26237cf006ab23823e9d58b818397ec7193",
            "5afdde537970926b24accdf2895d8be96545f6d7",
        ),
        (
            119,
            "31eba51c313a5c08226adf18d4a359cfdfd8d2e816b13f4af952f7ea6584dcfb",
            "3ae6a2ecf88f87d2ba38220c7208d58559daf7aaef7aa800ec118eac805567c6",
            "6c34b9e5f634dcdf42c6841102f786169b088b06",
        ),
        (
            120,
            "2f3d335432c70b580af0e8e1b3674a7c020d683aa5f73aaaedfdc55af904c21c",
            "09a712ac2347b5d613f9f3ad81a4659795a8c33070346be6891417a0932092e4",
            "656f97843ef5f33015d24e84156a1203ca716b03",
        ),
        (
            128,
            "6836cf13bac400e9105071cd6af47084dfacad4e5e302c94bfed24e013afb73e",
            "0fb4ba94ecf6f40f31757fab9f796e26595d45f0e143b7e97e376763031da930",
            "73641306aa8ea957e0a59897595aceecf405546b",
        ),
    ];
    let storage = [b'a'; 131];
    for (len, single, double, ripe) in vectors {
        let single = hex(single);
        let double = hex(double);
        let ripe = hex(ripe);
        for offset in 0..4 {
            let input = &storage[offset..offset + len];
            assert_eq!(sha256(input), single, "length {len}, offset {offset}");
            assert_eq!(sha256d(input), double, "length {len}, offset {offset}");
            assert_eq!(hash160(input), ripe, "length {len}, offset {offset}");
            for split in 0..=len {
                let next = (split + 1).min(len);
                assert_eq!(
                    sha256d_parts(&[&input[..split], &[], &input[split..next], &input[next..]]),
                    double,
                    "length {len}, offset {offset}, split {split}"
                );
            }
        }
    }
}

#[cfg(feature = "keccak")]
#[test]
fn keccak_known_answers_padding_and_alignment() {
    use planchet_primitives::keccak256;
    // Legacy Keccak padding, not the SHA3-256 domain separator.
    assert_eq!(
        keccak256(b""),
        hex("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470")
    );
    assert_eq!(
        keccak256(b"abc"),
        hex("4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45")
    );
    // PyCryptodome Crypto.Hash.keccak, independently generated outside Rust.
    let vectors = [
        (
            1,
            "3ac225168df54212a25c1c01fd35bebfea408fdac2e31ddd6f80a4bbf9a5f1cb",
        ),
        (
            135,
            "34367dc248bbd832f4e3e69dfaac2f92638bd0bbd18f2912ba4ef454919cf446",
        ),
        (
            136,
            "a6c4d403279fe3e0af03729caada8374b5ca54d8065329a3ebcaeb4b60aa386e",
        ),
        (
            137,
            "d869f639c7046b4929fc92a4d988a8b22c55fbadb802c0c66ebcd484f1915f39",
        ),
        (
            271,
            "132f47effd6c8b1b299efa53fe68aece77ec8ae4eb2e294f668eec94f76001e1",
        ),
        (
            272,
            "cf7fcd4f705ee749930d19ca84561a9bf62516bd90a471545fa2f49fdc7e63c8",
        ),
        (
            273,
            "5a7b8187d2778e614097fac3097573de1fee4d972304d3360796a857029bb176",
        ),
    ];
    let storage = [b'a'; 276];
    for (len, expected) in vectors {
        let expected = hex(expected);
        for offset in 0..4 {
            assert_eq!(
                keccak256(&storage[offset..offset + len]),
                expected,
                "length {len}, offset {offset}"
            );
        }
    }
}
