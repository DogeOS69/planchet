//! Bounded borrowed blocks and ordered, allocation-free transaction iteration.
use crate::{
    DecodeError, DecodeLimits, MerkleError, TxRef, WireHeader,
    decode::{Cursor, bound, exact},
    merkle_root_checked,
};
use core::iter::FusedIterator;
use planchet_primitives::{MerkleRoot, Txid};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlockRef<'a> {
    bytes: &'a [u8],
    header: WireHeader<'a>,
    tx_start: usize,
    tx_count: usize,
    limits: DecodeLimits,
}
impl<'a> BlockRef<'a> {
    pub fn decode_exact(bytes: &'a [u8], limits: DecodeLimits) -> Result<Self, DecodeError> {
        bound(bytes.len(), limits.max_block_bytes, "block bytes")?;
        let (header, header_len) = WireHeader::decode_prefix(bytes, limits)?;
        let mut c = Cursor::new(bytes, limits.max_block_bytes, "block bytes");
        c.take(header_len)?;
        let tx_count = c.count(limits.max_block_txs, "block transactions")?;
        if tx_count == 0 {
            return Err(DecodeError::EmptyBlock);
        }
        // Smallest accepted legacy transaction: 4+1+41+1+4 = 51 bytes.
        c.possible(tx_count, 51)?;
        let tx_start = c.pos;
        for _ in 0..tx_count {
            let (_, consumed) = TxRef::decode_prefix(&bytes[c.pos..], limits)?;
            c.take(consumed)?;
        }
        exact(c.pos, bytes.len())?;
        Ok(Self {
            bytes,
            header,
            tx_start,
            tx_count,
            limits,
        })
    }
    pub fn bytes(&self) -> &'a [u8] {
        self.bytes
    }
    pub fn header(&self) -> &WireHeader<'a> {
        &self.header
    }
    pub fn tx_count(&self) -> usize {
        self.tx_count
    }
    pub fn transactions(&self) -> Transactions<'a> {
        Transactions {
            bytes: &self.bytes[self.tx_start..],
            remaining: self.tx_count,
            limits: self.limits,
        }
    }
    /// Txids in the same order as the original block, with no cached allocation.
    pub fn txids(&self) -> Txids<'a> {
        Txids {
            transactions: self.transactions(),
        }
    }
    pub fn tx_merkle_root(&self) -> Result<MerkleRoot, MerkleError> {
        merkle_root_checked(self.txids())
    }
    pub fn check_tx_merkle_root(&self) -> Result<(), MerkleError> {
        let actual = self.tx_merkle_root()?;
        let expected = self.header.base().merkle_root;
        if actual == expected {
            Ok(())
        } else {
            Err(MerkleError::RootMismatch { expected, actual })
        }
    }
}

#[derive(Clone, Debug)]
pub struct Transactions<'a> {
    bytes: &'a [u8],
    remaining: usize,
    limits: DecodeLimits,
}
impl<'a> Iterator for Transactions<'a> {
    type Item = TxRef<'a>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }
        let (tx, consumed) =
            TxRef::decode_prefix(self.bytes, self.limits).expect("validated block transaction");
        self.bytes = &self.bytes[consumed..];
        self.remaining -= 1;
        Some(tx)
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.remaining, Some(self.remaining))
    }
}
impl ExactSizeIterator for Transactions<'_> {}
impl FusedIterator for Transactions<'_> {}

#[derive(Clone, Debug)]
pub struct Txids<'a> {
    transactions: Transactions<'a>,
}
impl Iterator for Txids<'_> {
    type Item = Txid;
    fn next(&mut self) -> Option<Self::Item> {
        self.transactions.next().map(|tx| tx.txid())
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        self.transactions.size_hint()
    }
}
impl ExactSizeIterator for Txids<'_> {}
impl FusedIterator for Txids<'_> {}
