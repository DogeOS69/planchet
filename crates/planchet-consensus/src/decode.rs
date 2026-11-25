//! Resource budgets and errors shared by wire decoders.
use core::fmt;

/// Explicit application budgets. Every byte/count limit is checked before use.
/// Prefix decoders bound the consumed object, not the supplied suffix.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DecodeLimits {
    pub max_tx_bytes: usize,
    pub max_inputs: usize,
    pub max_outputs: usize,
    pub max_script_bytes: usize,
    pub max_block_bytes: usize,
    pub max_block_txs: usize,
    pub max_header_bytes: usize,
    pub max_parent_coinbase_bytes: usize,
    pub max_merkle_branch_hashes: usize,
    pub max_witness_items: usize,
    pub max_witness_item_bytes: usize,
    /// Aggregate serialized witness bytes, including counts and item lengths.
    pub max_witness_bytes: usize,
}

impl Default for DecodeLimits {
    fn default() -> Self {
        Self {
            max_tx_bytes: 1_000_000,
            max_inputs: 25_000,
            max_outputs: 100_000,
            max_script_bytes: 1_000_000,
            max_block_bytes: 8_000_000,
            max_block_txs: 100_000,
            max_header_bytes: 4_100_000,
            max_parent_coinbase_bytes: 4_000_000,
            max_merkle_branch_hashes: 32,
            max_witness_items: 100_000,
            max_witness_item_bytes: 4_000_000,
            max_witness_bytes: 4_000_000,
        }
    }
}

/// Byte offsets are relative to the object being decoded (a nested transaction
/// has its own origin). Output value bits are preserved without monetary checks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecodeError {
    UnexpectedEof {
        offset: usize,
    },
    NonMinimalCompactSize {
        offset: usize,
    },
    LengthOverflow {
        offset: usize,
    },
    LimitExceeded {
        resource: &'static str,
        limit: usize,
    },
    TrailingBytes {
        consumed: usize,
        total: usize,
    },
    MissingInputs,
    WitnessNotAllowed,
    UnknownWitnessFlags {
        flags: u8,
    },
    NotCoinbase,
    EmptyBlock,
    BufferTooSmall {
        needed: usize,
        available: usize,
    },
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnexpectedEof { offset } => write!(f, "unexpected end at byte {offset}"),
            Self::NonMinimalCompactSize { offset } => {
                write!(f, "nonminimal CompactSize at byte {offset}")
            }
            Self::LengthOverflow { offset } => write!(f, "length overflow at byte {offset}"),
            Self::LimitExceeded { resource, limit } => {
                write!(f, "{resource} exceeds limit {limit}")
            }
            Self::TrailingBytes { consumed, total } => {
                write!(f, "trailing bytes after {consumed} of {total}")
            }
            Self::MissingInputs => f.write_str("legacy transaction has no inputs"),
            Self::WitnessNotAllowed => {
                f.write_str("witness encoding is not a native legacy transaction")
            }
            Self::UnknownWitnessFlags { flags } => write!(f, "unknown witness flags {flags:#x}"),
            Self::NotCoinbase => f.write_str("AuxPoW parent transaction is not a coinbase"),
            Self::EmptyBlock => f.write_str("block has no transactions"),
            Self::BufferTooSmall { needed, available } => {
                write!(f, "need {needed} output bytes, have {available}")
            }
        }
    }
}
impl core::error::Error for DecodeError {}

pub(crate) fn bound(value: usize, limit: usize, resource: &'static str) -> Result<(), DecodeError> {
    if value > limit {
        Err(DecodeError::LimitExceeded { resource, limit })
    } else {
        Ok(())
    }
}

pub(crate) fn exact(consumed: usize, total: usize) -> Result<(), DecodeError> {
    if consumed == total {
        Ok(())
    } else {
        Err(DecodeError::TrailingBytes { consumed, total })
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct Cursor<'a> {
    pub bytes: &'a [u8],
    pub pos: usize,
    limit: usize,
    resource: &'static str,
}

impl<'a> Cursor<'a> {
    pub fn new(bytes: &'a [u8], limit: usize, resource: &'static str) -> Self {
        Self {
            bytes,
            pos: 0,
            limit,
            resource,
        }
    }
    pub fn take(&mut self, n: usize) -> Result<&'a [u8], DecodeError> {
        let end = self
            .pos
            .checked_add(n)
            .ok_or(DecodeError::LengthOverflow { offset: self.pos })?;
        bound(end, self.limit, self.resource)?;
        let result = self
            .bytes
            .get(self.pos..end)
            .ok_or(DecodeError::UnexpectedEof { offset: self.pos })?;
        self.pos = end;
        Ok(result)
    }
    pub fn array<const N: usize>(&mut self) -> Result<[u8; N], DecodeError> {
        let mut bytes = [0; N];
        bytes.copy_from_slice(self.take(N)?);
        Ok(bytes)
    }
    pub fn u32(&mut self) -> Result<u32, DecodeError> {
        Ok(u32::from_le_bytes(self.array()?))
    }
    pub fn count(&mut self, limit: usize, resource: &'static str) -> Result<usize, DecodeError> {
        let (value, size) = crate::compact_size::decode_compact_size(
            &self.bytes[self.pos..],
            u64::MAX,
        )
        .map_err(|e| match e {
            DecodeError::NonMinimalCompactSize { offset } => DecodeError::NonMinimalCompactSize {
                offset: self.pos + offset,
            },
            DecodeError::UnexpectedEof { offset } => DecodeError::UnexpectedEof {
                offset: self.pos + offset,
            },
            other => other,
        })?;
        self.take(size)?;
        let value = usize::try_from(value).map_err(|_| DecodeError::LengthOverflow {
            offset: self.pos - size,
        })?;
        bound(value, limit, resource)?;
        Ok(value)
    }
    /// Preflight a vector's minimum wire size, preventing hostile-count loops.
    pub fn possible(&self, count: usize, minimum: usize) -> Result<(), DecodeError> {
        let remaining = self.bytes.len().min(self.limit).saturating_sub(self.pos);
        if count > remaining / minimum {
            Err(DecodeError::UnexpectedEof { offset: self.pos })
        } else {
            Ok(())
        }
    }
}
