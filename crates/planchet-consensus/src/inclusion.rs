//! Bounded transaction Merkle inclusion, not whole-tree validation.
//!
//! Counts and positions are u32, so at most 32 sibling hashes are consumed.
//! A branch supplies one sibling per level, including the duplicate of the
//! current hash at odd tails. Equal *real* siblings visible on this path are
//! rejected; mutations hidden inside a supplied subtree cannot be detected.
//! The caller must authenticate the root and leaf count separately.
use core::fmt;
use planchet_primitives::{MerkleRoot, Txid, sha256d};

pub const MAX_BRANCH_LENGTH: usize = 32;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InclusionError {
    EmptyTree,
    IndexOutOfRange,
    BranchTooLong,
    WrongBranchLength {
        expected: usize,
        actual: usize,
    },
    InvalidOddDuplicate {
        level: usize,
    },
    /// Equal real siblings on the supplied path only, not a whole-tree audit.
    EqualRealSiblings {
        level: usize,
    },
    RootMismatch,
}

impl fmt::Display for InclusionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyTree => f.write_str("Merkle tree has no leaves"),
            Self::IndexOutOfRange => f.write_str("Merkle leaf index is outside the tree"),
            Self::BranchTooLong => f.write_str("Merkle branch exceeds 32 levels"),
            Self::WrongBranchLength { expected, actual } => {
                write!(f, "expected {expected} Merkle siblings, got {actual}")
            }
            Self::InvalidOddDuplicate { level } => {
                write!(f, "invalid odd-tail duplicate at Merkle level {level}")
            }
            Self::EqualRealSiblings { level } => {
                write!(f, "equal real siblings at Merkle level {level}")
            }
            Self::RootMismatch => f.write_str("Merkle inclusion root mismatch"),
        }
    }
}
impl core::error::Error for InclusionError {}

/// Errors for BIP37 structure/root verification or MerkleBlock wire decoding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PartialMerkleError {
    Decode(crate::DecodeError),
    InvalidLeafCount,
    InvalidHashCount,
    MissingFlag,
    MissingHash,
    UnusedHashes,
    UnusedFlagBytes,
    DepthExceeded,
    EqualRealSiblings,
    RootMismatch,
}

impl fmt::Display for PartialMerkleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Decode(error) => error.fmt(f),
            other => f.write_str(match other {
                Self::InvalidLeafCount => "partial Merkle leaf count is zero or exceeds budget",
                Self::InvalidHashCount => {
                    "partial Merkle hashes must be nonempty whole hashes, at most leaf count"
                }
                Self::MissingFlag => "partial Merkle traversal ran out of flag bits",
                Self::MissingHash => "partial Merkle traversal ran out of hashes",
                Self::UnusedHashes => "partial Merkle traversal left unused hashes",
                Self::UnusedFlagBytes => "partial Merkle traversal left unused flag bytes",
                Self::DepthExceeded => "partial Merkle depth exceeds budget",
                Self::EqualRealSiblings => "partial Merkle traversal found equal real siblings",
                Self::RootMismatch => "partial Merkle root mismatch",
                Self::Decode(_) => unreachable!(),
            }),
        }
    }
}
impl core::error::Error for PartialMerkleError {}

/// BIP37 partial tree inputs, borrowed without allocation.
#[derive(Clone, Copy, Debug)]
pub struct PartialMerkleTreeRef<'a> {
    leaf_count: u32,
    hashes: &'a [u8],
    flags: &'a [u8],
}

impl<'a> PartialMerkleTreeRef<'a> {
    /// `hashes` contains concatenated 32-byte raw digests; `flags` is packed
    /// least-significant bit first. Construction alone does not validate them.
    pub const fn new(leaf_count: u32, hashes: &'a [u8], flags: &'a [u8]) -> Self {
        Self {
            leaf_count,
            hashes,
            flags,
        }
    }

    pub const fn leaf_count(&self) -> u32 {
        self.leaf_count
    }
    pub const fn hash_bytes(&self) -> &'a [u8] {
        self.hashes
    }
    pub const fn flag_bytes(&self) -> &'a [u8] {
        self.flags
    }

    /// Verify a pruned BIP37 tree against the supplied root, enforcing resource
    /// budgets, exact hash consumption, and exact flag-*byte* consumption.
    /// Unused bits in the final consumed byte are permitted, as in Core.
    ///
    /// Equal expanded real siblings are rejected. Pruned subtrees hide their
    /// internal mutations. Flags assert which leaves match; this cannot prove
    /// Bloom-filter correctness, completeness of matches, or authenticate the
    /// root/count. Hashing and traversal use no allocation, depth is at most 32,
    /// and work is bounded by `limits.max_block_txs` and available proof bytes.
    pub fn verify(
        self,
        root: MerkleRoot,
        limits: crate::DecodeLimits,
    ) -> Result<VerifiedPartialMerkleTree<'a>, PartialMerkleError> {
        let count =
            usize::try_from(self.leaf_count).map_err(|_| PartialMerkleError::InvalidLeafCount)?;
        if count == 0 || count > limits.max_block_txs {
            return Err(PartialMerkleError::InvalidLeafCount);
        }
        if self.hashes.is_empty()
            || !self.hashes.len().is_multiple_of(32)
            || self.hashes.len() / 32 > count
        {
            return Err(PartialMerkleError::InvalidHashCount);
        }
        for bytes in [self.hashes, self.flags] {
            crate::decode::bound(bytes.len(), limits.max_block_bytes, "partial Merkle bytes")
                .map_err(PartialMerkleError::Decode)?;
        }
        let height = u32::BITS - (self.leaf_count - 1).leading_zeros();
        if height as usize > limits.max_merkle_branch_hashes.min(MAX_BRANCH_LENGTH) {
            return Err(PartialMerkleError::DepthExceeded);
        }
        let mut cursor = PartialCursor {
            tree: self,
            bits: 0,
            hashes: 0,
            matched: 0,
        };
        let hash = cursor.walk(height, 0)?;
        if cursor.hashes != self.hashes.len() / 32 {
            return Err(PartialMerkleError::UnusedHashes);
        }
        if cursor.bits.div_ceil(8) != self.flags.len() {
            return Err(PartialMerkleError::UnusedFlagBytes);
        }
        if &hash != root.as_wire_bytes() {
            return Err(PartialMerkleError::RootMismatch);
        }
        Ok(VerifiedPartialMerkleTree {
            tree: self,
            height,
            root,
            matched: cursor.matched,
        })
    }
}

fn tree_width(count: u32, height: u32) -> u64 {
    u64::from(count).div_ceil(1u64 << height)
}

struct PartialCursor<'a> {
    tree: PartialMerkleTreeRef<'a>,
    bits: usize,
    hashes: usize,
    matched: usize,
}

impl PartialCursor<'_> {
    fn flag(&mut self) -> Result<bool, PartialMerkleError> {
        let byte = self
            .tree
            .flags
            .get(self.bits / 8)
            .ok_or(PartialMerkleError::MissingFlag)?;
        let flag = byte & (1 << (self.bits % 8)) != 0;
        self.bits += 1;
        Ok(flag)
    }

    fn hash(&mut self) -> Result<[u8; 32], PartialMerkleError> {
        let offset = self.hashes * 32;
        let bytes = self
            .tree
            .hashes
            .get(offset..offset + 32)
            .ok_or(PartialMerkleError::MissingHash)?;
        self.hashes += 1;
        Ok(bytes.try_into().expect("fixed hash slice"))
    }

    fn walk(&mut self, height: u32, pos: u64) -> Result<[u8; 32], PartialMerkleError> {
        let parent_match = self.flag()?;
        if height == 0 || !parent_match {
            if height == 0 && parent_match {
                self.matched += 1;
            }
            return self.hash();
        }
        let left = self.walk(height - 1, pos * 2)?;
        let right = if pos * 2 + 1 < tree_width(self.tree.leaf_count, height - 1) {
            let right = self.walk(height - 1, pos * 2 + 1)?;
            if left == right {
                return Err(PartialMerkleError::EqualRealSiblings);
            }
            right
        } else {
            left
        };
        let mut pair = [0; 64];
        pair[..32].copy_from_slice(&left);
        pair[32..].copy_from_slice(&right);
        Ok(sha256d(&pair))
    }
}

/// A partial tree checked against a root. This is not a verified block, and
/// neither the root nor the claimed transaction count is authenticated here.
#[derive(Clone, Copy, Debug)]
pub struct VerifiedPartialMerkleTree<'a> {
    tree: PartialMerkleTreeRef<'a>,
    height: u32,
    root: MerkleRoot,
    matched: usize,
}

impl<'a> VerifiedPartialMerkleTree<'a> {
    pub const fn root(&self) -> MerkleRoot {
        self.root
    }
    pub const fn leaf_count(&self) -> u32 {
        self.tree.leaf_count
    }

    /// Yield (leaf index, txid) in tree order, only after all verification has
    /// succeeded. A fixed stack bounds memory independently of match count.
    pub fn matched_transactions(&self) -> MatchedTransactions<'a> {
        let mut stack = [(0, 0); MAX_BRANCH_LENGTH + 1];
        stack[0] = (self.height, 0);
        MatchedTransactions {
            cursor: PartialCursor {
                tree: self.tree,
                bits: 0,
                hashes: 0,
                matched: 0,
            },
            stack,
            stack_len: 1,
            remaining: self.matched,
        }
    }
}

pub struct MatchedTransactions<'a> {
    cursor: PartialCursor<'a>,
    stack: [(u32, u64); MAX_BRANCH_LENGTH + 1],
    stack_len: usize,
    remaining: usize,
}

impl Iterator for MatchedTransactions<'_> {
    type Item = (u32, Txid);

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }
        while self.stack_len != 0 {
            self.stack_len -= 1;
            let (height, pos) = self.stack[self.stack_len];
            let flag = self.cursor.flag().expect("verified partial Merkle flags");
            if height == 0 || !flag {
                let hash = self.cursor.hash().expect("verified partial Merkle hashes");
                if height == 0 && flag {
                    self.remaining -= 1;
                    return Some((pos as u32, Txid::from_wire_bytes(hash)));
                }
            } else {
                // Push right before left for depth-first left-to-right order.
                if pos * 2 + 1 < tree_width(self.cursor.tree.leaf_count, height - 1) {
                    self.stack[self.stack_len] = (height - 1, pos * 2 + 1);
                    self.stack_len += 1;
                }
                self.stack[self.stack_len] = (height - 1, pos * 2);
                self.stack_len += 1;
            }
        }
        None
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.remaining, Some(self.remaining))
    }
}
impl ExactSizeIterator for MatchedTransactions<'_> {}
impl core::iter::FusedIterator for MatchedTransactions<'_> {}

/// Dogecoin MerkleBlock wire view, including a complete variable-size AuxPoW
/// header when flagged. Decoding only checks structure; call `verify` as well.
#[derive(Clone, Copy, Debug)]
pub struct MerkleBlockRef<'a> {
    header: crate::WireHeader<'a>,
    tree: PartialMerkleTreeRef<'a>,
}

impl<'a> MerkleBlockRef<'a> {
    pub fn decode_exact(
        bytes: &'a [u8],
        limits: crate::DecodeLimits,
    ) -> Result<Self, PartialMerkleError> {
        Self::decode_inner(bytes, limits).map_err(PartialMerkleError::Decode)
    }

    fn decode_inner(
        bytes: &'a [u8],
        limits: crate::DecodeLimits,
    ) -> Result<Self, crate::DecodeError> {
        crate::decode::bound(bytes.len(), limits.max_block_bytes, "MerkleBlock bytes")?;
        let (header, consumed) = crate::WireHeader::decode_prefix(bytes, limits)?;
        let mut cursor =
            crate::decode::Cursor::new(bytes, limits.max_block_bytes, "MerkleBlock bytes");
        cursor.take(consumed)?;
        let leaf_count = cursor.u32()?;
        crate::decode::bound(
            usize::try_from(leaf_count).map_err(|_| crate::DecodeError::LengthOverflow {
                offset: cursor.pos - 4,
            })?,
            limits.max_block_txs,
            "MerkleBlock transactions",
        )?;
        let hash_count = cursor.count(limits.max_block_txs, "partial Merkle hashes")?;
        cursor.possible(hash_count, 32)?;
        let hash_len = hash_count
            .checked_mul(32)
            .ok_or(crate::DecodeError::LengthOverflow { offset: cursor.pos })?;
        let hashes = cursor.take(hash_len)?;
        let flag_count = cursor.count(limits.max_block_bytes, "partial Merkle flag bytes")?;
        let flags = cursor.take(flag_count)?;
        crate::decode::exact(cursor.pos, bytes.len())?;
        Ok(Self {
            header,
            tree: PartialMerkleTreeRef::new(leaf_count, hashes, flags),
        })
    }

    pub const fn header(&self) -> &crate::WireHeader<'a> {
        &self.header
    }
    pub const fn tree(&self) -> PartialMerkleTreeRef<'a> {
        self.tree
    }
    pub fn verify(
        &self,
        limits: crate::DecodeLimits,
    ) -> Result<VerifiedPartialMerkleTree<'a>, PartialMerkleError> {
        self.tree.verify(self.header.base().merkle_root, limits)
    }
}

/// Verify one leaf at `index` in a `leaf_count`-leaf Bitcoin-style Merkle tree.
///
/// `branch` is in leaf-to-root order, in raw digest/wire byte order. Success
/// establishes this path under the supplied count, not transaction validity,
/// root authenticity, count authenticity, or absence of mutations elsewhere.
/// No allocation occurs and work is bounded by [`MAX_BRANCH_LENGTH`].
pub fn verify_inclusion(
    leaf: Txid,
    index: u32,
    leaf_count: u32,
    branch: &[[u8; 32]],
    root: MerkleRoot,
) -> Result<(), InclusionError> {
    if branch.len() > MAX_BRANCH_LENGTH {
        return Err(InclusionError::BranchTooLong);
    }
    if leaf_count == 0 {
        return Err(InclusionError::EmptyTree);
    }
    if index >= leaf_count {
        return Err(InclusionError::IndexOutOfRange);
    }
    let expected = (u32::BITS - (leaf_count - 1).leading_zeros()) as usize;
    if branch.len() != expected {
        return Err(InclusionError::WrongBranchLength {
            expected,
            actual: branch.len(),
        });
    }
    let mut hash = leaf.to_wire_bytes();
    let mut index = index;
    let mut width = leaf_count;
    for (level, sibling) in branch.iter().enumerate() {
        let odd_tail = width & 1 != 0 && index == width - 1;
        if odd_tail {
            if sibling != &hash {
                return Err(InclusionError::InvalidOddDuplicate { level });
            }
        } else if sibling == &hash {
            return Err(InclusionError::EqualRealSiblings { level });
        }
        let mut pair = [0; 64];
        let (left, right) = if index & 1 == 0 {
            (&hash, sibling)
        } else {
            (sibling, &hash)
        };
        pair[..32].copy_from_slice(left);
        pair[32..].copy_from_slice(right);
        hash = sha256d(&pair);
        index >>= 1;
        width = width / 2 + width % 2;
    }
    if &hash != root.as_wire_bytes() {
        return Err(InclusionError::RootMismatch);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> [u8; 32] {
        let mut bytes = [0; 32];
        for (i, byte) in bytes.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap();
        }
        bytes
    }

    // Golden raw digests generated independently with Python hashlib, using
    // leaves 01*32, 02*32, 03*32 and SHA256(SHA256(left || right)).
    fn ab() -> [u8; 32] {
        hex("39ce20bede82c96b8908bec4a157b09c549b3db90b9b474bda9ae9b9030310b4")
    }
    fn cc() -> [u8; 32] {
        hex("643d4b7e3699d2b3d8c9374b3600bdf1f573b799d2a56886236551a016b42ddf")
    }
    fn root() -> MerkleRoot {
        MerkleRoot::from_wire_bytes(hex(
            "223e023fadf1f053df26988871f893c821c28edf77d64a955e6c2a02d547bdac",
        ))
    }

    #[test]
    fn independent_three_leaf_paths_check_order_and_odd_duplication() {
        assert_eq!(
            verify_inclusion(
                Txid::from_wire_bytes([1; 32]),
                0,
                3,
                &[[2; 32], cc()],
                root()
            ),
            Ok(())
        );
        assert_eq!(
            verify_inclusion(
                Txid::from_wire_bytes([2; 32]),
                1,
                3,
                &[[1; 32], cc()],
                root()
            ),
            Ok(())
        );
        assert_eq!(
            verify_inclusion(
                Txid::from_wire_bytes([3; 32]),
                2,
                3,
                &[[3; 32], ab()],
                root()
            ),
            Ok(())
        );
        assert_eq!(
            verify_inclusion(
                Txid::from_wire_bytes([3; 32]),
                2,
                3,
                &[[4; 32], ab()],
                root()
            ),
            Err(InclusionError::InvalidOddDuplicate { level: 0 })
        );
        assert_eq!(
            verify_inclusion(
                Txid::from_wire_bytes([1; 32]),
                0,
                3,
                &[[3; 32], cc()],
                root()
            ),
            Err(InclusionError::RootMismatch)
        );
    }

    #[test]
    fn structural_bounds_and_singleton() {
        let leaf = Txid::from_wire_bytes([1; 32]);
        let root = MerkleRoot::from_wire_bytes([1; 32]);
        assert_eq!(verify_inclusion(leaf, 0, 1, &[], root), Ok(()));
        assert_eq!(
            verify_inclusion(leaf, 0, 0, &[], root),
            Err(InclusionError::EmptyTree)
        );
        assert_eq!(
            verify_inclusion(leaf, 1, 1, &[], root),
            Err(InclusionError::IndexOutOfRange)
        );
        assert_eq!(
            verify_inclusion(leaf, 0, 1, &[[0; 32]], root),
            Err(InclusionError::WrongBranchLength {
                expected: 0,
                actual: 1
            })
        );
        assert_eq!(
            verify_inclusion(leaf, 0, 3, &[[0; 32]], root),
            Err(InclusionError::WrongBranchLength {
                expected: 2,
                actual: 1
            })
        );
        assert_eq!(
            verify_inclusion(leaf, 0, u32::MAX, &[], root),
            Err(InclusionError::WrongBranchLength {
                expected: 32,
                actual: 0
            })
        );
        assert_eq!(
            verify_inclusion(leaf, 0, 1, &[[0; 32]; 33], root),
            Err(InclusionError::BranchTooLong)
        );
    }

    #[test]
    fn mutation_check_is_limited_to_the_supplied_path() {
        // The same root represents [a,b,c] or [a,b,c,c]. Path a cannot see
        // whether subtree cc was odd duplication or two real equal leaves.
        assert_eq!(
            verify_inclusion(
                Txid::from_wire_bytes([1; 32]),
                0,
                4,
                &[[2; 32], cc()],
                root()
            ),
            Ok(())
        );
        assert_eq!(
            verify_inclusion(
                Txid::from_wire_bytes([3; 32]),
                2,
                4,
                &[[3; 32], ab()],
                root()
            ),
            Err(InclusionError::EqualRealSiblings { level: 0 })
        );
    }

    #[test]
    fn bip37_odd_tree_extracts_matches_and_checks_all_consumption() {
        let mut hashes = [0; 96];
        hashes[..32].fill(1);
        hashes[32..64].fill(2);
        hashes[64..].fill(3);
        let limits = crate::DecodeLimits::default();
        // DFS flags: root, left parent, a, b, right parent, c. No flag
        // or hash is serialized for the absent right sibling of c.
        let proof = PartialMerkleTreeRef::new(3, &hashes, &[0x3f]);
        let checked = proof.verify(root(), limits).unwrap();
        let mut matches = checked.matched_transactions();
        assert_eq!(matches.len(), 3);
        assert_eq!(matches.next(), Some((0, Txid::from_wire_bytes([1; 32]))));
        assert_eq!(matches.next(), Some((1, Txid::from_wire_bytes([2; 32]))));
        assert_eq!(matches.next(), Some((2, Txid::from_wire_bytes([3; 32]))));
        assert_eq!(matches.next(), None);
        // Core allows unused bits in the last consumed flag byte.
        assert!(
            PartialMerkleTreeRef::new(3, &hashes, &[0xff])
                .verify(root(), limits)
                .is_ok()
        );
        assert_eq!(
            PartialMerkleTreeRef::new(3, &hashes, &[0x3f, 0])
                .verify(root(), limits)
                .unwrap_err(),
            PartialMerkleError::UnusedFlagBytes
        );
        assert_eq!(
            PartialMerkleTreeRef::new(3, &hashes, &[0])
                .verify(root(), limits)
                .unwrap_err(),
            PartialMerkleError::UnusedHashes
        );
        assert_eq!(
            PartialMerkleTreeRef::new(3, &hashes, &[])
                .verify(root(), limits)
                .unwrap_err(),
            PartialMerkleError::MissingFlag
        );
        assert_eq!(
            PartialMerkleTreeRef::new(3, &hashes[..32], &[0x3f])
                .verify(root(), limits)
                .unwrap_err(),
            PartialMerkleError::MissingHash
        );
        assert_eq!(
            proof.verify(MerkleRoot::ZERO, limits).unwrap_err(),
            PartialMerkleError::RootMismatch
        );
        assert_eq!(
            PartialMerkleTreeRef::new(0, &hashes, &[0])
                .verify(root(), limits)
                .unwrap_err(),
            PartialMerkleError::InvalidLeafCount
        );
        assert_eq!(
            PartialMerkleTreeRef::new(3, &hashes[..33], &[0])
                .verify(root(), limits)
                .unwrap_err(),
            PartialMerkleError::InvalidHashCount
        );
        assert_eq!(
            PartialMerkleTreeRef::new(2, &hashes, &[0])
                .verify(root(), limits)
                .unwrap_err(),
            PartialMerkleError::InvalidHashCount
        );
        assert_eq!(
            PartialMerkleTreeRef::new(2, &[1; 64], &[7])
                .verify(root(), limits)
                .unwrap_err(),
            PartialMerkleError::EqualRealSiblings
        );
    }

    #[test]
    fn bip37_pruning_and_depth_limits_do_not_imply_hidden_tree_validity() {
        let root = root();
        let mut limits = crate::DecodeLimits {
            max_block_txs: usize::MAX,
            ..crate::DecodeLimits::default()
        };
        let pruned = PartialMerkleTreeRef::new(u32::MAX, root.as_wire_bytes(), &[0]);
        let checked = pruned.verify(root, limits).unwrap();
        assert_eq!(checked.leaf_count(), u32::MAX);
        assert_eq!(checked.matched_transactions().next(), None);
        limits.max_merkle_branch_hashes = 31;
        assert_eq!(
            pruned.verify(root, limits).unwrap_err(),
            PartialMerkleError::DepthExceeded
        );
        // Pruned left subtree ab, expanded odd right subtree c.
        let mut hashes = [0; 64];
        hashes[..32].copy_from_slice(&ab());
        hashes[32..].fill(3);
        let checked = PartialMerkleTreeRef::new(3, &hashes, &[0x0d])
            .verify(root, limits)
            .unwrap();
        assert_eq!(
            checked.matched_transactions().next(),
            Some((2, Txid::from_wire_bytes([3; 32])))
        );
    }

    fn hex_bytes<const N: usize>(text: &str) -> [u8; N] {
        assert_eq!(text.len(), N * 2);
        let mut bytes = [0; N];
        for (i, byte) in bytes.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&text[i * 2..i * 2 + 2], 16).unwrap();
        }
        bytes
    }

    #[test]
    fn core_gettxoutproof_native_and_auxpow_merkleblocks_parse_completely() {
        // Dogecoin Core 1.14.9 regtest gettxoutproof recordings, generated and
        // verified by Core on 2026-11-24. Height 105 block ID:
        // 76189b4a0ef2e424c6a45972da5636733c60972e52f21944948d0332cfda707c
        // Height 106 (AuxPoW) block ID:
        // 76c8c746788452725dec232c8897bf56f0dab9e50c5cfe97ef105134b4a5a666
        // Complete expected wire bytes, matched txids, indices and header
        // lengths are embedded below, with no running Core dependency.
        let native = hex_bytes::<151>(
            "040062005be34fc49c86aba9fdc638cb1cd2d603ce0dea4296ca100815ec5752544d68d9f3fe93f720f16cf96be542404ffd491fc81c889fac98369ca8b26b02ecc34706fd70066bffff7f200000000002000000022ef118eb6d0de07c37a8c7a4dcf87221cf536a2fec6eff8a5a25f1cb05f815748be766f610516734675874e959b32f476cba8978b64895ab1fa479e76aa96d310105",
        );
        let auxpow = hex_bytes::<336>(
            "040162007c70dacf32038d944419f2522e97603c733656da7259a4c624e4f20e4a9b1876900b8f672ce044fe8db2377189fc5a5d145769deb0fc942721af550b360af68cfd70066bffff7f200000000001000000010000000000000000000000000000000000000000000000000000000000000000ffffffff2cfabe6d6d76c8c746788452725dec232c8897bf56f0dab9e50c5cfe97ef105134b4a5a6660100000000000000ffffffff0000000000f2d0d069c08bfb633ffeba26cc811d0b79b685e7c5aacdb7307cbf49161e1cb700000000000000000000010000000000000000000000000000000000000000000000000000000000000000000000d9c604833ff536d197cf4028fa9fc86ff0a158afbf687ca6354c91c0ccef82380000000000000000080000000100000001900b8f672ce044fe8db2377189fc5a5d145769deb0fc942721af550b360af68c0101",
        );
        let limits = crate::DecodeLimits::default();
        for (bytes, header_len, index, txid) in [
            (
                &native[..],
                80,
                1,
                "316da96ae779a41fab9548b67889ba6c472fb359e974586734675110f666e78b",
            ),
            (
                &auxpow[..],
                297,
                0,
                "8cf60a360b55af212794fcb0de6957145d5afc897137b28dfe44e02c678f0b90",
            ),
        ] {
            let block = MerkleBlockRef::decode_exact(bytes, limits).unwrap();
            assert_eq!(block.header().bytes().len(), header_len);
            let checked = block.verify(limits).unwrap();
            assert_eq!(checked.root(), block.header().base().merkle_root);
            let mut matched = checked.matched_transactions();
            assert_eq!(matched.len(), 1);
            assert_eq!(
                matched.next(),
                Some((index, Txid::from_rpc_hex(txid).unwrap()))
            );
            assert_eq!(matched.next(), None);
            assert!(MerkleBlockRef::decode_exact(&bytes[..bytes.len() - 1], limits).is_err());
        }
        let mut trailing = [0; 152];
        trailing[..151].copy_from_slice(&native);
        assert!(matches!(
            MerkleBlockRef::decode_exact(&trailing, limits),
            Err(PartialMerkleError::Decode(
                crate::DecodeError::TrailingBytes { .. }
            ))
        ));
        // The AuxPoW payload is required; reading a fixed 80-byte header is
        // insufficient to locate this proof's transaction count.
        assert!(MerkleBlockRef::decode_exact(&auxpow[..80], limits).is_err());
    }
}
