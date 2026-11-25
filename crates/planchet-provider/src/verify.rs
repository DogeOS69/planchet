use crate::Error;
use planchet_consensus::{BlockRef, DecodeLimits};
use planchet_primitives::BlockHash;

/// An observation of successful structural decoding, block ID and transaction Merkle checking.
/// This is not a proof of work or active-chain/finality assertion.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlockCheck {
    pub block_hash: BlockHash,
    pub byte_len: usize,
}

/// Supported offline raw-block check, using exactly the same consensus path as the node reader.
/// `expected` is an optional externally trusted block ID.
pub fn check_raw_block(bytes: &[u8], expected: Option<BlockHash>) -> Result<BlockCheck, Error> {
    let block = BlockRef::decode_exact(bytes, DecodeLimits::default()).map_err(|_| {
        Error::InvalidBlock {
            reason: "wire decode or resource limits",
        }
    })?;
    let block_hash = block.header().block_id();
    if let Some(expected) = expected
        && expected != block_hash
    {
        return Err(Error::HashMismatch {
            expected,
            actual: block_hash,
        });
    }
    block
        .check_tx_merkle_root()
        .map_err(|_| Error::InvalidBlock {
            reason: "transaction Merkle root mismatch or mutation",
        })?;
    Ok(BlockCheck {
        block_hash,
        byte_len: bytes.len(),
    })
}
