//! Dogecoin value types with explicit byte order and units.
//!
//! All APIs, including address formatting and decimal parsing, work without an
//! allocator with the portable software provider. `crypto-backend` enables
//! application provider installation independently of optional algorithms.
//! `keccak` exposes Keccak-256 (distinct from SHA3-256).
//! Hash IDs display in RPC order; signing digests display in digest order.
#![no_std]
#![forbid(unsafe_code)]

#[cfg(feature = "alloc")]
extern crate alloc;

pub mod address;
pub mod amount;
pub mod hash;
pub mod network;

pub use address::{Address, AddressError, AddressKind};
pub use amount::{Amount, FeeRate, ParseAmountError};
#[cfg(feature = "keccak")]
pub use hash::keccak256;
pub use hash::{
    BlockHash, Hash160, MerkleRoot, ParseHashError, Sighash, Txid, hash160, sha256, sha256_parts,
    sha256d, sha256d_parts,
};
pub use network::{ChainParams, Network, ParseNetworkError};

/// A transaction output identified by its wire-order transaction ID and output index.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct OutPoint {
    pub txid: Txid,
    pub vout: u32,
}

impl OutPoint {
    /// The coinbase null outpoint (all-zero ID and index `u32::MAX`).
    pub const NULL: Self = Self::new(Txid::ZERO, u32::MAX);

    pub const fn new(txid: Txid, vout: u32) -> Self {
        Self { txid, vout }
    }

    pub fn is_null(self) -> bool {
        self == Self::NULL
    }
}
