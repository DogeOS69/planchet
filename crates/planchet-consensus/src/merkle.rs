//! Constant-space transaction Merkle roots with duplicate-sibling detection.
use core::fmt;
use planchet_primitives::{MerkleRoot, Txid, sha256d};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MerkleError {
    Empty,
    Mutated,
    TooManyLeaves,
    RootMismatch {
        expected: MerkleRoot,
        actual: MerkleRoot,
    },
}
impl fmt::Display for MerkleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("empty transaction Merkle tree"),
            Self::Mutated => f.write_str("mutated transaction Merkle tree: equal real siblings"),
            Self::TooManyLeaves => f.write_str("transaction leaf count overflows usize"),
            Self::RootMismatch { .. } => f.write_str("transaction Merkle root differs from header"),
        }
    }
}
impl core::error::Error for MerkleError {}

fn pair(left: [u8; 32], right: [u8; 32]) -> [u8; 32] {
    let mut bytes = [0; 64];
    bytes[..32].copy_from_slice(&left);
    bytes[32..].copy_from_slice(&right);
    sha256d(&bytes)
}

/// Ordered, nonempty leaves. O(n) hashes, O(log usize::MAX) fixed stack, no heap.
/// Equal real siblings at any level are rejected before padding; an unpaired
/// odd tail may be duplicated. Iterator size hints never drive allocation.
pub fn merkle_root_checked(
    txids: impl IntoIterator<Item = Txid>,
) -> Result<MerkleRoot, MerkleError> {
    let mut inner = [[0u8; 32]; usize::BITS as usize];
    let mut count = 0usize;
    for txid in txids {
        let mut node = txid.to_wire_bytes();
        let next = count.checked_add(1).ok_or(MerkleError::TooManyLeaves)?;
        let mut level = 0;
        let mut occupied = count;
        while occupied & 1 != 0 {
            if inner[level] == node {
                return Err(MerkleError::Mutated);
            }
            node = pair(inner[level], node);
            occupied >>= 1;
            level += 1;
        }
        inner[level] = node;
        count = next;
    }
    if count == 0 {
        return Err(MerkleError::Empty);
    }
    // Fold occupied subtrees from right to left, padding only the odd tail.
    let mut level = count.trailing_zeros() as usize;
    let mut node = inner[level];
    for (next_level, left) in inner.iter().enumerate().skip(level + 1) {
        if (count >> next_level) & 1 != 0 {
            while level < next_level {
                node = pair(node, node);
                level += 1;
            }
            node = pair(*left, node);
            level += 1;
        }
    }
    Ok(MerkleRoot::from_wire_bytes(node))
}
