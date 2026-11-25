//! Native 80-byte headers and complete borrowed AuxPoW wire headers.
use crate::{
    DecodeError, DecodeLimits, Inputs, Outputs,
    borrowed::{Layout, inputs, outputs, scan_body},
    decode::{Cursor, bound, exact},
};
use core::{iter::FusedIterator, ops::Range};
use planchet_primitives::{BlockHash, MerkleRoot, Txid, sha256d};
use sha2::{Digest, Sha256};

pub const BASE_HEADER_LEN: usize = 80;
pub const AUXPOW_VERSION_FLAG: i32 = 1 << 8;

/// The fields hashed for a block ID, even for a merge-mined block.
/// `bits` retains the raw compact target; decoding does not validate PoW.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BaseHeader {
    pub version: i32,
    pub prev_blockhash: BlockHash,
    pub merkle_root: MerkleRoot,
    pub time: u32,
    pub bits: u32,
    pub nonce: u32,
}
impl BaseHeader {
    pub fn decode_exact(bytes: &[u8]) -> Result<Self, DecodeError> {
        let (header, consumed) = Self::decode_prefix(bytes)?;
        exact(consumed, bytes.len())?;
        Ok(header)
    }
    pub fn decode_prefix(bytes: &[u8]) -> Result<(Self, usize), DecodeError> {
        let mut c = Cursor::new(bytes, BASE_HEADER_LEN, "base header bytes");
        let header = Self {
            version: c.u32()? as i32,
            prev_blockhash: BlockHash::from_wire_bytes(c.array()?),
            merkle_root: MerkleRoot::from_wire_bytes(c.array()?),
            time: c.u32()?,
            bits: c.u32()?,
            nonce: c.u32()?,
        };
        Ok((header, c.pos))
    }
    pub fn is_auxpow(&self) -> bool {
        self.version & AUXPOW_VERSION_FLAG != 0
    }
    pub fn encode(&self) -> [u8; BASE_HEADER_LEN] {
        let mut bytes = [0; BASE_HEADER_LEN];
        bytes[..4].copy_from_slice(&self.version.to_le_bytes());
        bytes[4..36].copy_from_slice(&self.prev_blockhash.to_wire_bytes());
        bytes[36..68].copy_from_slice(&self.merkle_root.to_wire_bytes());
        bytes[68..72].copy_from_slice(&self.time.to_le_bytes());
        bytes[72..76].copy_from_slice(&self.bits.to_le_bytes());
        bytes[76..80].copy_from_slice(&self.nonce.to_le_bytes());
        bytes
    }
    /// SHA256d of the 80-byte child header. This is not the scrypt PoW hash.
    pub fn block_id(&self) -> BlockHash {
        BlockHash::from_wire_bytes(sha256d(&self.encode()))
    }
}

/// A complete checked header. Private fields keep the version flag and presence
/// of an AuxPoW trailer consistent. The parent header is always exactly 80 bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WireHeader<'a> {
    bytes: &'a [u8],
    base: BaseHeader,
    auxpow: Option<AuxPowRef<'a>>,
}
impl<'a> WireHeader<'a> {
    pub fn decode_exact(bytes: &'a [u8], limits: DecodeLimits) -> Result<Self, DecodeError> {
        bound(bytes.len(), limits.max_header_bytes, "header bytes")?;
        let (header, consumed) = Self::decode_prefix(bytes, limits)?;
        exact(consumed, bytes.len())?;
        Ok(header)
    }
    pub fn decode_prefix(
        bytes: &'a [u8],
        limits: DecodeLimits,
    ) -> Result<(Self, usize), DecodeError> {
        bound(BASE_HEADER_LEN, limits.max_header_bytes, "header bytes")?;
        let (base, mut consumed) = BaseHeader::decode_prefix(bytes)?;
        let auxpow = if base.is_auxpow() {
            // Restrict the parser's input to the total header budget before
            // parsing a variable-size parent coinbase or either branch.
            let end = bytes.len().min(limits.max_header_bytes);
            let (auxpow, size) = AuxPowRef::decode_prefix(&bytes[consumed..end], limits)?;
            consumed = consumed
                .checked_add(size)
                .ok_or(DecodeError::LengthOverflow { offset: consumed })?;
            Some(auxpow)
        } else {
            None
        };
        bound(consumed, limits.max_header_bytes, "header bytes")?;
        Ok((
            Self {
                bytes: &bytes[..consumed],
                base,
                auxpow,
            },
            consumed,
        ))
    }
    pub fn bytes(&self) -> &'a [u8] {
        self.bytes
    }
    pub fn base(&self) -> &BaseHeader {
        &self.base
    }
    pub fn auxpow(&self) -> Option<&AuxPowRef<'a>> {
        self.auxpow.as_ref()
    }
    pub fn block_id(&self) -> BlockHash {
        self.base.block_id()
    }
    /// Re-encode the native fields and copy the validated, byte-preserving
    /// auxiliary payload. Does not omit parent witness or either branch.
    pub fn encode_into(&self, out: &mut [u8]) -> Result<usize, DecodeError> {
        let needed = self.bytes.len();
        if out.len() < needed {
            return Err(DecodeError::BufferTooSmall {
                needed,
                available: out.len(),
            });
        }
        out[..BASE_HEADER_LEN].copy_from_slice(&self.base.encode());
        if let Some(auxpow) = self.auxpow() {
            out[BASE_HEADER_LEN..needed].copy_from_slice(auxpow.bytes());
        }
        Ok(needed)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MerkleBranch<'a> {
    bytes: &'a [u8],
}
impl<'a> MerkleBranch<'a> {
    fn decode(c: &mut Cursor<'a>, limits: DecodeLimits) -> Result<Self, DecodeError> {
        let count = c.count(limits.max_merkle_branch_hashes, "AuxPoW branch hashes")?;
        c.possible(count, 32)?;
        let len = count
            .checked_mul(32)
            .ok_or(DecodeError::LengthOverflow { offset: c.pos })?;
        Ok(Self {
            bytes: c.take(len)?,
        })
    }
    pub fn bytes(&self) -> &'a [u8] {
        self.bytes
    }
    pub fn len(&self) -> usize {
        self.bytes.len() / 32
    }
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
    /// Hashes in wire order, from the leaf toward the root.
    pub fn hashes(
        &self,
    ) -> impl ExactSizeIterator<Item = [u8; 32]> + DoubleEndedIterator + FusedIterator + 'a {
        self.bytes
            .chunks_exact(32)
            .map(|hash| hash.try_into().expect("validated branch hash"))
    }
}

/// Decoded auxiliary data, not proof of the parent/child mining commitments.
/// The legacy `parent_block_hash` field is retained without assuming it matches
/// the included parent header. Signed branch indices are retained verbatim.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuxPowRef<'a> {
    bytes: &'a [u8],
    coinbase: ParentCoinbaseRef<'a>,
    parent_block_hash: BlockHash,
    coinbase_branch: MerkleBranch<'a>,
    coinbase_index: i32,
    chain_branch: MerkleBranch<'a>,
    chain_index: i32,
    parent_header: BaseHeader,
}
impl<'a> AuxPowRef<'a> {
    pub fn decode_exact(bytes: &'a [u8], limits: DecodeLimits) -> Result<Self, DecodeError> {
        bound(bytes.len(), limits.max_header_bytes, "AuxPoW bytes")?;
        let (auxpow, consumed) = Self::decode_prefix(bytes, limits)?;
        exact(consumed, bytes.len())?;
        Ok(auxpow)
    }
    pub fn decode_prefix(
        bytes: &'a [u8],
        limits: DecodeLimits,
    ) -> Result<(Self, usize), DecodeError> {
        let capped = &bytes[..bytes.len().min(limits.max_header_bytes)];
        let (coinbase, size) = ParentCoinbaseRef::decode_prefix(capped, limits)?;
        let mut c = Cursor::new(capped, limits.max_header_bytes, "AuxPoW bytes");
        c.take(size)?;
        let parent_block_hash = BlockHash::from_wire_bytes(c.array()?);
        let coinbase_branch = MerkleBranch::decode(&mut c, limits)?;
        let coinbase_index = c.u32()? as i32;
        let chain_branch = MerkleBranch::decode(&mut c, limits)?;
        let chain_index = c.u32()? as i32;
        let parent_header = BaseHeader::decode_exact(c.take(BASE_HEADER_LEN)?)?;
        Ok((
            Self {
                bytes: &bytes[..c.pos],
                coinbase,
                parent_block_hash,
                coinbase_branch,
                coinbase_index,
                chain_branch,
                chain_index,
                parent_header,
            },
            c.pos,
        ))
    }
    pub fn bytes(&self) -> &'a [u8] {
        self.bytes
    }
    pub fn coinbase(&self) -> &ParentCoinbaseRef<'a> {
        &self.coinbase
    }
    pub fn parent_block_hash(&self) -> BlockHash {
        self.parent_block_hash
    }
    pub fn coinbase_branch(&self) -> MerkleBranch<'a> {
        self.coinbase_branch
    }
    pub fn coinbase_index(&self) -> i32 {
        self.coinbase_index
    }
    pub fn chain_branch(&self) -> MerkleBranch<'a> {
        self.chain_branch
    }
    pub fn chain_index(&self) -> i32 {
        self.chain_index
    }
    pub fn parent_header(&self) -> &BaseHeader {
        &self.parent_header
    }
}

/// Separate from native `TxRef`: the parent coinbase may use witness encoding.
/// Zero outputs and an empty witness stack are accepted by the pinned Core
/// 1.14.9 wire reader. A single null-outpoint input is required here.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ParentCoinbaseRef<'a> {
    bytes: &'a [u8],
    layout: Layout,
    body_start: usize,
    witness_start: usize,
    witness_count: usize,
    witness_items_start: usize,
    witness_encoding: bool,
}
impl<'a> ParentCoinbaseRef<'a> {
    pub fn decode_exact(bytes: &'a [u8], limits: DecodeLimits) -> Result<Self, DecodeError> {
        bound(
            bytes.len(),
            limits.max_parent_coinbase_bytes,
            "parent coinbase bytes",
        )?;
        let (tx, consumed) = Self::decode_prefix(bytes, limits)?;
        exact(consumed, bytes.len())?;
        Ok(tx)
    }
    pub fn decode_prefix(
        bytes: &'a [u8],
        limits: DecodeLimits,
    ) -> Result<(Self, usize), DecodeError> {
        let mut c = Cursor::new(
            bytes,
            limits.max_parent_coinbase_bytes,
            "parent coinbase bytes",
        );
        c.take(4)?;
        let mut body_start = c.pos;
        let mut count = c.count(limits.max_inputs, "parent inputs")?;
        let witness_encoding = count == 0;
        if witness_encoding {
            let flags = c.take(1)?[0];
            if flags == 0 {
                return Err(DecodeError::NotCoinbase);
            }
            if flags != 1 {
                return Err(DecodeError::UnknownWitnessFlags { flags });
            }
            body_start = c.pos;
            count = c.count(limits.max_inputs, "parent inputs")?;
        }
        if count != 1 {
            return Err(DecodeError::NotCoinbase);
        }
        let mut layout = scan_body(&mut c, count, limits)?;
        if !inputs(bytes, layout)
            .next()
            .is_some_and(|input| input.is_coinbase())
        {
            return Err(DecodeError::NotCoinbase);
        }
        let witness_start = c.pos;
        let mut witness_count = 0;
        let mut witness_items_start = c.pos;
        if witness_encoding {
            witness_count = c.count(limits.max_witness_items, "parent witness items")?;
            bound(
                c.pos - witness_start,
                limits.max_witness_bytes,
                "parent witness bytes",
            )?;
            c.possible(witness_count, 1)?;
            witness_items_start = c.pos;
            for _ in 0..witness_count {
                let len = c.count(limits.max_witness_item_bytes, "parent witness item bytes")?;
                let total = (c.pos - witness_start)
                    .checked_add(len)
                    .ok_or(DecodeError::LengthOverflow { offset: c.pos })?;
                bound(total, limits.max_witness_bytes, "parent witness bytes")?;
                c.take(len)?;
            }
        }
        layout.lock_time_start = c.pos;
        c.take(4)?;
        Ok((
            Self {
                bytes: &bytes[..c.pos],
                layout,
                body_start,
                witness_start,
                witness_count,
                witness_items_start,
                witness_encoding,
            },
            c.pos,
        ))
    }
    pub fn bytes(&self) -> &'a [u8] {
        self.bytes
    }
    pub fn version(&self) -> i32 {
        i32::from_le_bytes(self.bytes[..4].try_into().expect("validated version"))
    }
    pub fn lock_time(&self) -> u32 {
        u32::from_le_bytes(
            self.bytes[self.layout.lock_time_start..][..4]
                .try_into()
                .expect("validated locktime"),
        )
    }
    pub fn inputs(&self) -> Inputs<'a> {
        inputs(self.bytes, self.layout)
    }
    pub fn outputs(&self) -> Outputs<'a> {
        outputs(self.bytes, self.layout)
    }
    pub fn input_count(&self) -> usize {
        self.layout.input_count
    }
    pub fn output_count(&self) -> usize {
        self.layout.output_count
    }
    pub fn has_witness_encoding(&self) -> bool {
        self.witness_encoding
    }
    pub fn witness_bytes(&self) -> &'a [u8] {
        &self.bytes[self.witness_start..self.layout.lock_time_start]
    }
    pub fn witness_range(&self) -> Range<usize> {
        self.witness_start..self.layout.lock_time_start
    }
    pub fn witness_items(&self) -> WitnessItems<'a> {
        let mut cursor = Cursor::new(self.bytes, self.layout.lock_time_start, "validated witness");
        cursor.pos = self.witness_items_start;
        WitnessItems {
            cursor,
            remaining: self.witness_count,
        }
    }
    /// Parent txid excludes marker, flags, and witness, even when retained in wire bytes.
    pub fn txid(&self) -> Txid {
        if !self.witness_encoding {
            return Txid::from_wire_bytes(sha256d(self.bytes));
        }
        let mut hash = Sha256::new();
        hash.update(&self.bytes[..4]);
        hash.update(&self.bytes[self.body_start..self.layout.outputs_end]);
        hash.update(&self.bytes[self.layout.lock_time_start..]);
        Txid::from_wire_bytes(Sha256::digest(hash.finalize()).into())
    }
}

#[derive(Clone, Debug)]
pub struct WitnessItems<'a> {
    cursor: Cursor<'a>,
    remaining: usize,
}
impl<'a> Iterator for WitnessItems<'a> {
    type Item = &'a [u8];
    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }
        let len = self
            .cursor
            .count(usize::MAX, "validated witness")
            .expect("validated witness item length");
        let item = self.cursor.take(len).expect("validated witness item");
        self.remaining -= 1;
        Some(item)
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.remaining, Some(self.remaining))
    }
}
impl ExactSizeIterator for WitnessItems<'_> {}
impl FusedIterator for WitnessItems<'_> {}
